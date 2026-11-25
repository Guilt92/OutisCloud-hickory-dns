//! Explicit offline migration for legacy DNSSEC PEM key directories.
//!
//! Usage: `DNSSEC_KEY_ENCRYPTION_KEY=<base64-32-byte-key> cargo run -p hickory-key-store --bin migrate-dnssec-keys -- <key-dir>`

use std::{env, path::Path};

fn main() {
    if let Err(error) = run() {
        eprintln!("key migration failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args_os().skip(1);
    let directory = args
        .next()
        .ok_or("usage: migrate-dnssec-keys <key-directory>")?;
    if args.next().is_some() {
        return Err("usage: migrate-dnssec-keys <key-directory>".into());
    }
    let encoded = env::var("DNSSEC_KEY_ENCRYPTION_KEY")
        .map_err(|_| "DNSSEC_KEY_ENCRYPTION_KEY must be supplied through a secret manager")?;
    let key = hickory_key_store::parse_wrapping_key(&encoded)?;
    let migrated = hickory_key_store::migrate_directory(Path::new(&directory), &key)?;
    println!("encrypted {migrated} legacy DNSSEC key file(s)");
    Ok(())
}
