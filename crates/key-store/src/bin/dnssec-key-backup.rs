//! Explicit DNSSEC key backup and restore tool.
//!
//! `backup <key-directory> <new-archive-path> [recovery-manifest.json]` writes
//! an encrypted archive without replacing an existing file. When supplied,
//! the manifest is encrypted in the same archive and restored beside the keys.
//! `restore <archive-path> <new-directory>` restores only into a new directory.

use std::{env, fs, io::Write, path::Path};

fn main() {
    if let Err(error) = run() {
        eprintln!("DNSSEC key backup operation failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args_os().skip(1);
    let operation = args.next().ok_or(
        "usage: dnssec-key-backup <backup|restore> <source> <destination> [manifest.json]",
    )?;
    let source = args.next().ok_or("source path is required")?;
    let destination = args.next().ok_or("destination path is required")?;
    let manifest = args.next();
    if args.next().is_some() || (operation == "restore" && manifest.is_some()) {
        return Err(
            "usage: dnssec-key-backup <backup|restore> <source> <destination> [manifest.json]"
                .into(),
        );
    }
    let key = hickory_key_store::configured_wrapping_key()?;
    match operation.to_str() {
        Some("backup") => {
            let archive = if let Some(manifest) = manifest {
                let manifest = fs::read(manifest)?;
                hickory_key_store::create_encrypted_backup_with_manifest(
                    Path::new(&source),
                    &key,
                    &manifest,
                )?
            } else {
                hickory_key_store::create_encrypted_backup(Path::new(&source), &key)?
            };
            #[cfg(unix)]
            use std::os::unix::fs::OpenOptionsExt;
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            options.mode(0o600);
            let mut output = options.open(&destination)?;
            if let Err(error) = output.write_all(&archive).and_then(|_| output.sync_all()) {
                drop(output);
                let _ = fs::remove_file(&destination);
                return Err(error.into());
            }
            println!("wrote encrypted backup archive");
        }
        Some("restore") => {
            let archive = fs::read(&source)?;
            let count = hickory_key_store::restore_encrypted_backup(
                &archive,
                Path::new(&destination),
                &key,
            )?;
            println!("restored {count} DNSSEC key file(s) into a new directory");
        }
        _ => return Err("operation must be backup or restore".into()),
    }
    Ok(())
}
