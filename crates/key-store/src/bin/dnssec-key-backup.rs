//! Explicit DNSSEC key backup and restore tool.
//!
//! `backup <key-directory> <new-archive-path>` writes an encrypted archive
//! without replacing an existing file. `restore <archive-path> <new-directory>`
//! restores only into a previously absent directory.

use std::{env, fs, io::Write, path::Path};

fn main() {
    if let Err(error) = run() {
        eprintln!("DNSSEC key backup operation failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args_os().skip(1);
    let operation = args
        .next()
        .ok_or("usage: dnssec-key-backup <backup|restore> <source> <destination>")?;
    let source = args.next().ok_or("source path is required")?;
    let destination = args.next().ok_or("destination path is required")?;
    if args.next().is_some() {
        return Err("usage: dnssec-key-backup <backup|restore> <source> <destination>".into());
    }
    let encoded = env::var("DNSSEC_KEY_ENCRYPTION_KEY")
        .map_err(|_| "DNSSEC_KEY_ENCRYPTION_KEY must be supplied through a secret manager")?;
    let key = hickory_key_store::parse_wrapping_key(&encoded)?;
    match operation.to_str() {
        Some("backup") => {
            let archive = hickory_key_store::create_encrypted_backup(Path::new(&source), &key)?;
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
