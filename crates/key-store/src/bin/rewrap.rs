//! Offline DNSSEC wrapping-key rotation into a separate key tree.
//! Supply old and new base64 keys through private files; switch deployment
//! configuration only after verifying the new tree and a recovery copy.

use std::{env, fs, path::Path};

fn load_key(path: &Path) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err("wrapping-key source must be a regular non-symlink file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("wrapping-key file must be private to its owner".into());
        }
    }
    Ok(hickory_key_store::parse_wrapping_key(&fs::read_to_string(
        path,
    )?)?)
}

fn main() {
    if let Err(error) = run() {
        eprintln!("DNSSEC key rotation failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    if args.len() != 4 {
        return Err(
            "usage: rewrap-dnssec-keys <source-dir> <new-dir> <old-key-file> <new-key-file>".into(),
        );
    }
    let old_key = load_key(Path::new(&args[2]))?;
    let new_key = load_key(Path::new(&args[3]))?;
    let count = hickory_key_store::rewrap_directory(
        Path::new(&args[0]),
        Path::new(&args[1]),
        &old_key,
        &new_key,
    )?;
    println!("rotated {count} DNSSEC key file(s) into a new directory");
    Ok(())
}
