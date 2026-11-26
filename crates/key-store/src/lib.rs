//! Encrypted-at-rest storage primitives for DNSSEC private keys.
//!
//! The wrapping key is injected by the deployment through
//! `DNSSEC_KEY_ENCRYPTION_KEY` as base64 encoding of exactly 32 random bytes,
//! or `DNSSEC_KEY_ENCRYPTION_KEY_FILE` pointing to a private mounted secret
//! containing that encoding. Configure exactly one source. Keep the secret
//! separate from zone files and database backups. The envelope uses AES-256-GCM and an
//! authenticated version header. Legacy plaintext files can be read while
//! migrating; setting `DNSSEC_REQUIRE_ENCRYPTED_KEYS=true` rejects them and
//! also requires the wrapping key for newly written keys.

use ring::{
    aead,
    rand::{SecureRandom, SystemRandom},
};
use std::{env, fs, io, path::Path};

const MAGIC: &[u8] = b"OUTIS-DNSSEC-KEY\0\x01";
const KEY_ENV: &str = "DNSSEC_KEY_ENCRYPTION_KEY";
const KEY_FILE_ENV: &str = "DNSSEC_KEY_ENCRYPTION_KEY_FILE";
const REQUIRE_ENV: &str = "DNSSEC_REQUIRE_ENCRYPTED_KEYS";
const NONCE_LEN: usize = 12;
const BACKUP_MAGIC: &[u8] = b"OUTIS-DNSSEC-BACKUP\0\x01";
const MAX_BACKUP_BYTES: usize = 64 * 1024 * 1024;
const MAX_BACKUP_FILES: usize = 10_000;

#[derive(Debug)]
pub enum KeyStoreError {
    Configuration(String),
    Crypto,
    Io(io::Error),
}

impl std::fmt::Display for KeyStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Configuration(error) => f.write_str(error),
            Self::Crypto => f.write_str("DNSSEC key envelope authentication failed"),
            Self::Io(error) => write!(f, "DNSSEC key file operation failed: {error}"),
        }
    }
}

impl std::error::Error for KeyStoreError {}

impl From<io::Error> for KeyStoreError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

fn require_encryption() -> bool {
    env::var(REQUIRE_ENV)
        .map(|value| value.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn configured_key() -> Result<Option<[u8; 32]>, KeyStoreError> {
    let encoded = env::var(KEY_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty());
    let key_file = env::var_os(KEY_FILE_ENV).filter(|value| !value.is_empty());
    if encoded.is_some() && key_file.is_some() {
        return Err(KeyStoreError::Configuration(format!(
            "configure only one of {KEY_ENV} and {KEY_FILE_ENV}"
        )));
    }
    if let Some(encoded) = encoded {
        return parse_wrapping_key(&encoded).map(Some);
    }
    let Some(path) = key_file else {
        return Ok(None);
    };
    let path = Path::new(&path);
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(KeyStoreError::Configuration(format!(
            "{KEY_FILE_ENV} must reference a regular, non-symlink file"
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(KeyStoreError::Configuration(format!(
                "{KEY_FILE_ENV} permissions must not grant group or other access"
            )));
        }
    }
    let encoded = fs::read_to_string(path)?;
    parse_wrapping_key(encoded.trim()).map(Some)
}

/// Load the wrapping key from the configured secret-manager environment or
/// private mounted secret file. Offline tools use this instead of requiring a
/// second environment-specific key-loading implementation.
pub fn configured_wrapping_key() -> Result<[u8; 32], KeyStoreError> {
    configured_key()?.ok_or_else(|| {
        KeyStoreError::Configuration(format!(
            "{KEY_ENV} or {KEY_FILE_ENV} is required to access DNSSEC backups"
        ))
    })
}

/// Parse a base64 encoded 256-bit wrapping key for explicit offline tooling.
pub fn parse_wrapping_key(encoded: &str) -> Result<[u8; 32], KeyStoreError> {
    let decoded = data_encoding::BASE64
        .decode(encoded.trim().as_bytes())
        .map_err(|_| {
            KeyStoreError::Configuration("wrapping key must be base64 for 32 random bytes".into())
        })?;
    decoded.try_into().map_err(|_| {
        KeyStoreError::Configuration("wrapping key must be base64 for 32 random bytes".into())
    })
}

fn encrypt_with_nonce(
    plaintext: &[u8],
    key_bytes: &[u8; 32],
    nonce_bytes: [u8; NONCE_LEN],
) -> Result<Vec<u8>, KeyStoreError> {
    let key =
        aead::UnboundKey::new(&aead::AES_256_GCM, key_bytes).map_err(|_| KeyStoreError::Crypto)?;
    let key = aead::LessSafeKey::new(key);
    let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
    let mut ciphertext = plaintext.to_vec();
    key.seal_in_place_append_tag(nonce, aead::Aad::from(MAGIC), &mut ciphertext)
        .map_err(|_| KeyStoreError::Crypto)?;
    let mut envelope = Vec::with_capacity(MAGIC.len() + NONCE_LEN + ciphertext.len());
    envelope.extend_from_slice(MAGIC);
    envelope.extend_from_slice(&nonce_bytes);
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

pub fn encrypt_with_key(plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, KeyStoreError> {
    let mut nonce = [0u8; NONCE_LEN];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| KeyStoreError::Crypto)?;
    encrypt_with_nonce(plaintext, key, nonce)
}

pub fn decrypt_with_key(envelope: &[u8], key_bytes: &[u8; 32]) -> Result<Vec<u8>, KeyStoreError> {
    if !envelope.starts_with(MAGIC)
        || envelope.len() < MAGIC.len() + NONCE_LEN + aead::AES_256_GCM.tag_len()
    {
        return Err(KeyStoreError::Crypto);
    }
    let nonce_start = MAGIC.len();
    let nonce_end = nonce_start + NONCE_LEN;
    let nonce_bytes: [u8; NONCE_LEN] = envelope[nonce_start..nonce_end]
        .try_into()
        .map_err(|_| KeyStoreError::Crypto)?;
    let key =
        aead::UnboundKey::new(&aead::AES_256_GCM, key_bytes).map_err(|_| KeyStoreError::Crypto)?;
    let key = aead::LessSafeKey::new(key);
    let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
    let mut ciphertext = envelope[nonce_end..].to_vec();
    let plaintext = key
        .open_in_place(nonce, aead::Aad::from(MAGIC), &mut ciphertext)
        .map_err(|_| KeyStoreError::Crypto)?;
    Ok(plaintext.to_vec())
}

/// Encrypt for storage when a wrapping key is configured. Legacy deployments
/// remain readable until they set `DNSSEC_REQUIRE_ENCRYPTED_KEYS=true`.
pub fn encrypt_configured(plaintext: &[u8]) -> Result<Vec<u8>, KeyStoreError> {
    match configured_key()? {
        Some(key) => encrypt_with_key(plaintext, &key),
        None if require_encryption() => Err(KeyStoreError::Configuration(format!(
            "{KEY_ENV} is required when {REQUIRE_ENV}=true"
        ))),
        None => Ok(plaintext.to_vec()),
    }
}

/// Decrypt versioned envelopes, or return a legacy plaintext key while
/// migration is enabled. No key bytes or secret values are included in errors.
pub fn decrypt_configured(stored: &[u8]) -> Result<Vec<u8>, KeyStoreError> {
    if !stored.starts_with(MAGIC) {
        return if require_encryption() {
            Err(KeyStoreError::Configuration(format!(
                "plaintext DNSSEC key rejected because {REQUIRE_ENV}=true"
            )))
        } else {
            Ok(stored.to_vec())
        };
    }
    let key = configured_key()?.ok_or_else(|| {
        KeyStoreError::Configuration(format!("{KEY_ENV} is required to decrypt DNSSEC keys"))
    })?;
    decrypt_with_key(stored, &key)
}

/// Atomically encrypt legacy key files in a key directory. Already encrypted
/// files are left untouched. The caller must first verify a separate recovery
/// copy and keep the wrapping key outside this directory.
pub fn migrate_directory(directory: &Path, key: &[u8; 32]) -> Result<usize, KeyStoreError> {
    let mut migrated = 0;
    migrate_directory_inner(directory, key, &mut migrated)?;
    Ok(migrated)
}

/// Re-encrypt an existing key tree under a new wrapping key. The destination
/// must be a new directory outside the source. All source envelopes are
/// authenticated before creating the destination, so an incorrect old key
/// cannot produce a partially rotated tree.
pub fn rewrap_directory(
    source: &Path,
    destination: &Path,
    old_key: &[u8; 32],
    new_key: &[u8; 32],
) -> Result<usize, KeyStoreError> {
    if old_key == new_key {
        return Err(KeyStoreError::Configuration(
            "new wrapping key must differ from old key".into(),
        ));
    }
    if fs::symlink_metadata(source)?.file_type().is_symlink() {
        return Err(KeyStoreError::Configuration(
            "source must be a regular directory".into(),
        ));
    }
    let source = source.canonicalize()?;
    if !source.is_dir() {
        return Err(KeyStoreError::Configuration(
            "source must be a regular directory".into(),
        ));
    }
    let parent = destination
        .parent()
        .ok_or_else(|| KeyStoreError::Configuration("destination needs a parent directory".into()))?
        .canonicalize()?;
    if parent.starts_with(&source) {
        return Err(KeyStoreError::Configuration(
            "destination must be outside the source tree".into(),
        ));
    }
    let name = destination
        .file_name()
        .ok_or_else(|| KeyStoreError::Configuration("destination needs a directory name".into()))?;
    let destination = parent.join(name);
    if destination.exists() || fs::symlink_metadata(&destination).is_ok() {
        return Err(KeyStoreError::Configuration(
            "destination already exists".into(),
        ));
    }
    let mut files = Vec::new();
    collect_key_files(&source, &source, &mut files)?;
    let mut plaintext = Vec::with_capacity(files.len());
    for (path, bytes) in files {
        plaintext.push((path, decrypt_with_key(&bytes, old_key)?));
    }
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    fs::create_dir(&destination)?;
    #[cfg(unix)]
    fs::set_permissions(&destination, fs::Permissions::from_mode(0o700))?;
    let result = (|| {
        for (path, bytes) in &plaintext {
            let target = destination.join(path);
            let parent = target.parent().ok_or(KeyStoreError::Crypto)?;
            fs::create_dir_all(parent)?;
            #[cfg(unix)]
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
            atomic_replace(&target, &encrypt_with_key(bytes, new_key)?)?;
        }
        Ok::<(), KeyStoreError>(())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&destination);
    }
    result?;
    Ok(plaintext.len())
}

/// Create a single authenticated backup containing all regular `.pem` files
/// below a DNSSEC key directory. Symlinks and oversized trees are rejected.
pub fn create_encrypted_backup(directory: &Path, key: &[u8; 32]) -> Result<Vec<u8>, KeyStoreError> {
    create_encrypted_backup_inner(directory, key, None)
}

/// Create an encrypted key backup that also carries a caller-produced recovery
/// manifest (for example, the matching DNSSEC database metadata snapshot).
/// The manifest is encrypted inside the same authenticated archive and is
/// restored as `recovery-manifest.json` beside the keys.
pub fn create_encrypted_backup_with_manifest(
    directory: &Path,
    key: &[u8; 32],
    manifest: &[u8],
) -> Result<Vec<u8>, KeyStoreError> {
    if manifest.len() > MAX_BACKUP_BYTES {
        return Err(KeyStoreError::Configuration(
            "DNSSEC recovery manifest exceeds the 64 MiB limit".into(),
        ));
    }
    create_encrypted_backup_inner(directory, key, Some(manifest))
}

fn create_encrypted_backup_inner(
    directory: &Path,
    key: &[u8; 32],
    manifest: Option<&[u8]>,
) -> Result<Vec<u8>, KeyStoreError> {
    let mut files = Vec::new();
    collect_key_files(directory, directory, &mut files)?;
    if files.len() + usize::from(manifest.is_some()) > MAX_BACKUP_FILES {
        return Err(KeyStoreError::Configuration(
            "too many DNSSEC key files for backup".into(),
        ));
    }
    if let Some(manifest) = manifest {
        files.push((
            std::path::PathBuf::from("recovery-manifest.json"),
            manifest.to_vec(),
        ));
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    let mut payload = BACKUP_MAGIC.to_vec();
    payload.extend_from_slice(&(files.len() as u32).to_be_bytes());
    for (relative, bytes) in files {
        let name = relative
            .to_str()
            .ok_or_else(|| KeyStoreError::Configuration("key path is not UTF-8".into()))?
            .as_bytes();
        if name.len() > u16::MAX as usize
            || bytes.len() > u32::MAX as usize
            || payload.len() + name.len() + bytes.len() + 6 > MAX_BACKUP_BYTES
        {
            return Err(KeyStoreError::Configuration(
                "DNSSEC backup exceeds the 64 MiB limit".into(),
            ));
        }
        payload.extend_from_slice(&(name.len() as u16).to_be_bytes());
        payload.extend_from_slice(name);
        payload.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        payload.extend_from_slice(&bytes);
    }
    encrypt_with_key(&payload, key)
}

/// Restore an authenticated backup into a new directory. Existing destinations
/// are never overwritten; on an I/O failure only the new directory created by
/// this call is removed. The caller can verify and atomically activate it.
pub fn restore_encrypted_backup(
    archive: &[u8],
    destination: &Path,
    key: &[u8; 32],
) -> Result<usize, KeyStoreError> {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    if archive.len() > MAX_BACKUP_BYTES + MAGIC.len() + NONCE_LEN + aead::AES_256_GCM.tag_len() {
        return Err(KeyStoreError::Configuration(
            "DNSSEC backup exceeds the 64 MiB limit".into(),
        ));
    }
    let payload = decrypt_with_key(archive, key)?;
    let mut cursor = 0;
    if take(&payload, &mut cursor, BACKUP_MAGIC.len())? != BACKUP_MAGIC {
        return Err(KeyStoreError::Crypto);
    }
    let count = u32::from_be_bytes(
        take(&payload, &mut cursor, 4)?
            .try_into()
            .map_err(|_| KeyStoreError::Crypto)?,
    ) as usize;
    if count > MAX_BACKUP_FILES {
        return Err(KeyStoreError::Configuration(
            "too many DNSSEC key files in backup".into(),
        ));
    }
    let mut files = Vec::with_capacity(count);
    for _ in 0..count {
        let name_len = u16::from_be_bytes(
            take(&payload, &mut cursor, 2)?
                .try_into()
                .map_err(|_| KeyStoreError::Crypto)?,
        ) as usize;
        let name = std::str::from_utf8(take(&payload, &mut cursor, name_len)?)
            .map_err(|_| KeyStoreError::Crypto)?;
        let relative = Path::new(name);
        let is_manifest = relative == Path::new("recovery-manifest.json");
        if relative.as_os_str().is_empty()
            || relative.is_absolute()
            || relative
                .components()
                .any(|part| !matches!(part, std::path::Component::Normal(_)))
            || (!is_manifest && relative.extension().and_then(|ext| ext.to_str()) != Some("pem"))
        {
            return Err(KeyStoreError::Configuration(
                "unsafe path in DNSSEC backup".into(),
            ));
        }
        let data_len = u32::from_be_bytes(
            take(&payload, &mut cursor, 4)?
                .try_into()
                .map_err(|_| KeyStoreError::Crypto)?,
        ) as usize;
        let data = take(&payload, &mut cursor, data_len)?.to_vec();
        files.push((relative.to_path_buf(), data));
    }
    if cursor != payload.len() {
        return Err(KeyStoreError::Crypto);
    }
    fs::create_dir(destination)?;
    #[cfg(unix)]
    if let Err(error) = fs::set_permissions(destination, fs::Permissions::from_mode(0o700)) {
        let _ = fs::remove_dir(destination);
        return Err(error.into());
    }
    let write_result = (|| {
        for (relative, bytes) in &files {
            let target = destination.join(relative);
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
                #[cfg(unix)]
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
            }
            atomic_replace(&target, bytes)?;
        }
        Ok::<(), KeyStoreError>(())
    })();
    if let Err(error) = write_result {
        let _ = fs::remove_dir_all(destination);
        return Err(error);
    }
    Ok(files
        .iter()
        .filter(|(path, _)| path.extension().and_then(|ext| ext.to_str()) == Some("pem"))
        .count())
}

fn collect_key_files(
    root: &Path,
    directory: &Path,
    files: &mut Vec<(std::path::PathBuf, Vec<u8>)>,
) -> Result<(), KeyStoreError> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_symlink() {
            return Err(KeyStoreError::Configuration(
                "symlinks are not allowed in DNSSEC key directories".into(),
            ));
        }
        if kind.is_dir() {
            collect_key_files(root, &entry.path(), files)?;
        } else if kind.is_file()
            && entry.path().extension().and_then(|ext| ext.to_str()) == Some("pem")
        {
            if files.len() >= MAX_BACKUP_FILES {
                return Err(KeyStoreError::Configuration(
                    "too many DNSSEC key files for backup".into(),
                ));
            }
            let bytes = fs::read(entry.path())?;
            if bytes.len() > MAX_BACKUP_BYTES {
                return Err(KeyStoreError::Configuration(
                    "DNSSEC backup exceeds the 64 MiB limit".into(),
                ));
            }
            files.push((
                entry
                    .path()
                    .strip_prefix(root)
                    .map_err(|_| KeyStoreError::Crypto)?
                    .to_path_buf(),
                bytes,
            ));
        }
    }
    Ok(())
}

fn take<'a>(bytes: &'a [u8], cursor: &mut usize, len: usize) -> Result<&'a [u8], KeyStoreError> {
    let end = cursor.checked_add(len).ok_or(KeyStoreError::Crypto)?;
    let value = bytes.get(*cursor..end).ok_or(KeyStoreError::Crypto)?;
    *cursor = end;
    Ok(value)
}

fn migrate_directory_inner(
    directory: &Path,
    key: &[u8; 32],
    migrated: &mut usize,
) -> Result<(), KeyStoreError> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let kind = entry.file_type()?;
        if kind.is_symlink() {
            return Err(KeyStoreError::Configuration(
                "symlinks are not allowed in DNSSEC key directories".into(),
            ));
        }
        if kind.is_dir() {
            migrate_directory_inner(&path, key, migrated)?;
            continue;
        }
        if !kind.is_file() || path.extension().and_then(|ext| ext.to_str()) != Some("pem") {
            continue;
        }
        let bytes = fs::read(&path)?;
        if bytes.starts_with(MAGIC) {
            continue;
        }
        let envelope = encrypt_with_key(&bytes, key)?;
        atomic_replace(&path, &envelope)?;
        *migrated += 1;
    }
    Ok(())
}

fn atomic_replace(path: &Path, bytes: &[u8]) -> Result<(), KeyStoreError> {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let suffix = format!("{}.{}.tmp", std::process::id(), uuid_suffix());
    let mut tmp_name = path.file_name().unwrap_or_default().to_os_string();
    tmp_name.push(".");
    tmp_name.push(suffix);
    let tmp = path.with_file_name(tmp_name);
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&tmp)?;
    if let Err(error) = file.write_all(bytes).and_then(|_| file.sync_all()) {
        let _ = fs::remove_file(&tmp);
        return Err(error.into());
    }
    drop(file);
    if let Err(error) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(error.into());
    }
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    if let Some(parent) = path.parent() {
        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

fn uuid_suffix() -> String {
    let mut bytes = [0u8; 8];
    if SystemRandom::new().fill(&mut bytes).is_err() {
        // The PID still distinguishes concurrent processes; the monotonic
        // counter avoids collisions within a process if the OS RNG fails.
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        return COUNTER
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            .to_string();
    }
    data_encoding::HEXLOWER.encode(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn encrypted_envelope_round_trips_and_rejects_tampering() {
        let key = [7u8; 32];
        let plaintext = b"private key bytes that must not be stored in the envelope";
        let envelope = encrypt_with_key(plaintext, &key).unwrap();
        assert!(envelope.starts_with(MAGIC));
        assert!(!envelope.windows(plaintext.len()).any(|w| w == plaintext));
        assert_eq!(decrypt_with_key(&envelope, &key).unwrap(), plaintext);
        assert!(decrypt_with_key(&envelope, &[8u8; 32]).is_err());
        let mut tampered = envelope;
        *tampered.last_mut().unwrap() ^= 1;
        assert!(decrypt_with_key(&tampered, &key).is_err());
    }

    #[test]
    fn configured_encryption_fails_closed_and_round_trips() {
        let _guard = ENV_LOCK.lock().unwrap();
        let old_key = env::var_os(KEY_ENV);
        let old_key_file = env::var_os(KEY_FILE_ENV);
        let old_required = env::var_os(REQUIRE_ENV);
        env::remove_var(KEY_ENV);
        env::remove_var(KEY_FILE_ENV);
        env::set_var(REQUIRE_ENV, "true");
        assert!(encrypt_configured(b"secret").is_err());
        assert!(decrypt_configured(b"legacy plaintext").is_err());

        let wrapping_key = [0x31u8; 32];
        env::set_var(KEY_ENV, data_encoding::BASE64.encode(&wrapping_key));
        let stored = encrypt_configured(b"private key").unwrap();
        assert!(stored.starts_with(MAGIC));
        assert_eq!(decrypt_configured(&stored).unwrap(), b"private key");

        match old_key {
            Some(value) => env::set_var(KEY_ENV, value),
            None => env::remove_var(KEY_ENV),
        }
        match old_key_file {
            Some(value) => env::set_var(KEY_FILE_ENV, value),
            None => env::remove_var(KEY_FILE_ENV),
        }
        match old_required {
            Some(value) => env::set_var(REQUIRE_ENV, value),
            None => env::remove_var(REQUIRE_ENV),
        }
    }

    #[cfg(unix)]
    #[test]
    fn mounted_wrapping_key_requires_private_regular_file_and_rejects_ambiguous_sources() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let _guard = ENV_LOCK.lock().unwrap();
        let old_key = env::var_os(KEY_ENV);
        let old_key_file = env::var_os(KEY_FILE_ENV);
        env::remove_var(KEY_ENV);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wrapping-key");
        let wrapping_key = [0x62u8; 32];
        fs::write(&path, data_encoding::BASE64.encode(&wrapping_key)).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        env::set_var(KEY_FILE_ENV, &path);
        assert_eq!(configured_wrapping_key().unwrap(), wrapping_key);

        let encrypted = encrypt_configured(b"file-mounted secret").unwrap();
        assert_eq!(
            decrypt_configured(&encrypted).unwrap(),
            b"file-mounted secret"
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
        assert!(
            configured_key().is_err(),
            "world-readable wrapping keys are rejected"
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        let link = dir.path().join("key-link");
        symlink(&path, &link).unwrap();
        env::set_var(KEY_FILE_ENV, &link);
        assert!(
            configured_key().is_err(),
            "symlinked wrapping keys are rejected"
        );

        env::set_var(KEY_ENV, data_encoding::BASE64.encode(&wrapping_key));
        env::set_var(KEY_FILE_ENV, &path);
        assert!(
            configured_key().is_err(),
            "ambiguous key sources are rejected"
        );
        match old_key {
            Some(value) => env::set_var(KEY_ENV, value),
            None => env::remove_var(KEY_ENV),
        }
        match old_key_file {
            Some(value) => env::set_var(KEY_FILE_ENV, value),
            None => env::remove_var(KEY_FILE_ENV),
        }
    }

    #[test]
    fn migration_is_atomic_idempotent_and_includes_retired_keys() {
        let dir = tempfile::tempdir().unwrap();
        let retired = dir.path().join("retired");
        fs::create_dir(&retired).unwrap();
        fs::write(dir.path().join("active.pem"), b"active legacy key").unwrap();
        fs::write(retired.join("retired.pem"), b"retired legacy key").unwrap();
        fs::write(dir.path().join("README"), b"not a key").unwrap();
        let key = [9u8; 32];
        assert_eq!(migrate_directory(dir.path(), &key).unwrap(), 2);
        assert_eq!(migrate_directory(dir.path(), &key).unwrap(), 0);
        assert_eq!(
            decrypt_with_key(&fs::read(dir.path().join("active.pem")).unwrap(), &key).unwrap(),
            b"active legacy key"
        );
        assert_eq!(
            decrypt_with_key(&fs::read(retired.join("retired.pem")).unwrap(), &key).unwrap(),
            b"retired legacy key"
        );
        assert_eq!(fs::read(dir.path().join("README")).unwrap(), b"not a key");
    }

    #[test]
    fn encrypted_backup_restores_to_new_tree_without_plaintext_leakage() {
        let source = tempfile::tempdir().unwrap();
        let retired = source.path().join("retired");
        fs::create_dir(&retired).unwrap();
        fs::write(source.path().join("active.pem"), b"active secret").unwrap();
        fs::write(retired.join("retired.pem"), b"retired secret").unwrap();
        fs::write(source.path().join("readme"), b"not a key").unwrap();
        let key = [0x73u8; 32];
        let backup = create_encrypted_backup(source.path(), &key).unwrap();
        assert!(
            !backup
                .windows(b"active secret".len())
                .any(|w| w == b"active secret")
        );
        restore_encrypted_backup(&backup, &source.path().join("restored"), &key).unwrap();
        assert_eq!(
            fs::read(source.path().join("restored/active.pem")).unwrap(),
            b"active secret"
        );
        assert_eq!(
            fs::read(source.path().join("restored/retired/retired.pem")).unwrap(),
            b"retired secret"
        );
        assert!(restore_encrypted_backup(&backup, &source.path().join("restored"), &key).is_err());
        assert!(
            restore_encrypted_backup(&backup, &source.path().join("wrong-key"), &[0x74u8; 32])
                .is_err()
        );
    }

    #[test]
    fn rewrap_authenticates_all_keys_and_preserves_source_on_failure() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        fs::create_dir(&source).unwrap();
        fs::create_dir(source.join("retired")).unwrap();
        let old = [0x11; 32];
        let new = [0x22; 32];
        let active = encrypt_with_key(b"active", &old).unwrap();
        let retired = encrypt_with_key(b"retired", &old).unwrap();
        fs::write(source.join("active.pem"), &active).unwrap();
        fs::write(source.join("retired/old.pem"), &retired).unwrap();
        let bad_dest = root.path().join("bad");
        assert!(rewrap_directory(&source, &bad_dest, &[0x33; 32], &new).is_err());
        assert!(!bad_dest.exists());
        assert_eq!(fs::read(source.join("active.pem")).unwrap(), active);
        let destination = root.path().join("rotated");
        assert_eq!(
            rewrap_directory(&source, &destination, &old, &new).unwrap(),
            2
        );
        assert_eq!(
            decrypt_with_key(&fs::read(destination.join("active.pem")).unwrap(), &new).unwrap(),
            b"active"
        );
        assert_eq!(
            decrypt_with_key(
                &fs::read(destination.join("retired/old.pem")).unwrap(),
                &new
            )
            .unwrap(),
            b"retired"
        );
        assert!(
            decrypt_with_key(&fs::read(destination.join("active.pem")).unwrap(), &old).is_err()
        );
        assert!(rewrap_directory(&source, &destination, &old, &new).is_err());
        assert!(rewrap_directory(&source, &source.join("nested"), &old, &new).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(destination.join("active.pem"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn recovery_manifest_is_encrypted_and_restored_with_key_snapshot() {
        let source = tempfile::tempdir().unwrap();
        fs::write(source.path().join("active.pem"), b"private material").unwrap();
        let manifest =
            br#"{"format":1,"zone_id":"test-zone","keys":[{"tag":42,"status":"active"}]}"#;
        let key = [0x63u8; 32];
        let archive = create_encrypted_backup_with_manifest(source.path(), &key, manifest).unwrap();
        assert!(
            !archive
                .windows(manifest.len())
                .any(|window| window == manifest)
        );
        assert_eq!(
            restore_encrypted_backup(&archive, &source.path().join("restored"), &key).unwrap(),
            1
        );
        assert_eq!(
            fs::read(source.path().join("restored/recovery-manifest.json")).unwrap(),
            manifest
        );
        assert_eq!(
            fs::read(source.path().join("restored/active.pem")).unwrap(),
            b"private material"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(source.path().join("restored/recovery-manifest.json"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn migration_rejects_symlinked_key_inputs() {
        let dir = tempfile::tempdir().unwrap();
        let key_dir = dir.path().join("keys");
        fs::create_dir(&key_dir).unwrap();
        let outside = dir.path().join("outside.pem");
        fs::write(&outside, b"must not be followed").unwrap();
        std::os::unix::fs::symlink(&outside, key_dir.join("linked.pem")).unwrap();
        assert!(migrate_directory(&key_dir, &[0x45u8; 32]).is_err());
        assert_eq!(fs::read(outside).unwrap(), b"must not be followed");
    }
}
