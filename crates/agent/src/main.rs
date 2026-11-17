//! OutisCloud DNS agent.
//!
//! Registers nothing by itself: an administrator registers the agent in the
//! dashboard/API and hands it `AGENT_ID`, `AGENT_TOKEN` and `AGENT_SIGNING_KEY`.
//! The agent then
//!   1. heartbeats (every `HEARTBEAT_SECS`); the answer says which bundle
//!      version is wanted and whether an immediate sync was requested,
//!   2. fetches the signed bundle when it is behind,
//!   3. verifies hash + HMAC signature + file names, stages the files and
//!      swaps them into place atomically (named.toml last), keeping the last
//!      known-good files on any error,
//!   4. acknowledges the version (or the error) so the control plane shows the
//!      real state. The DNS server's own file watcher then reloads the zones.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::{error, info, warn};

type HmacSha256 = Hmac<Sha256>;
const ZONE_DIR_TOKEN: &str = "@ZONE_DIR@";

#[derive(Debug, Deserialize)]
pub struct BundleFile {
    pub name: String,
    pub content: String,
}

#[derive(Debug, Deserialize)]
pub struct Bundle {
    pub version: i64,
    pub hash: String,
    pub signature: String,
    pub files: Vec<BundleFile>,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// Content hash; must match the control plane's `bundle_hash`.
pub fn bundle_hash(files: &[BundleFile]) -> String {
    let mut h = Sha256::new();
    for f in files {
        h.update((f.name.len() as u64).to_be_bytes());
        h.update(f.name.as_bytes());
        h.update((f.content.len() as u64).to_be_bytes());
        h.update(f.content.as_bytes());
    }
    hex(&h.finalize())
}

/// HMAC over version, hash and the framed files; must match `sign_bundle` of the control plane.
pub fn sign(key: &str, version: i64, hash: &str, files: &[BundleFile]) -> String {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key.as_bytes()).expect("hmac key");
    mac.update(format!("v1|{}|{}|", version, hash).as_bytes());
    for f in files {
        mac.update(format!("{}:{}|", f.name.len(), f.name).as_bytes());
        mac.update(format!("{}:", f.content.len()).as_bytes());
        mac.update(f.content.as_bytes());
    }
    hex(&mac.finalize().into_bytes())
}

/// Constant-time comparison of two hex strings.
fn eq_ct(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

pub fn verify(key: &str, b: &Bundle) -> Result<(), String> {
    if bundle_hash(&b.files) != b.hash {
        return Err("bundle hash does not match its content".into());
    }
    if !eq_ct(&sign(key, b.version, &b.hash, &b.files), &b.signature) {
        return Err("bundle signature is invalid (wrong key or tampered bundle)".into());
    }
    for f in &b.files {
        let ok_name = f.name == "named.toml"
            || (f.name.starts_with("zone.")
                && !f.name.contains('/')
                && !f.name.contains('\\')
                && !f.name.contains("..")
                && !f.name.ends_with(".tmp"));
        if !ok_name {
            return Err(format!("unexpected file name in bundle: {:?}", f.name));
        }
    }
    if !b.files.iter().any(|f| f.name == "named.toml") {
        return Err("bundle has no named.toml".into());
    }
    Ok(())
}

fn write_synced(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let mut f = fs::File::create(path)?;
    f.write_all(data)?;
    f.sync_all()
}

/// Install a verified bundle into `dir`. Everything is staged first; the
/// previous files are only replaced once the whole bundle was written
/// successfully. Zone files go first, `named.toml` last, so the DNS server
/// never sees a configuration that points at a missing zone file.
pub fn apply(dir: &Path, b: &Bundle) -> Result<(), String> {
    fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let stage = dir.join(format!(".staging-{}", b.version));
    let _ = fs::remove_dir_all(&stage);
    fs::create_dir_all(&stage).map_err(|e| format!("cannot create staging dir: {e}"))?;
    let abs = dir.to_string_lossy().trim_end_matches('/').to_string();
    let result = (|| -> Result<(), String> {
        for f in &b.files {
            let content = if f.name == "named.toml" {
                f.content.replace(ZONE_DIR_TOKEN, &abs)
            } else {
                f.content.clone()
            };
            write_synced(&stage.join(&f.name), content.as_bytes())
                .map_err(|e| format!("staging {}: {e}", f.name))?;
        }
        // swap zone files in, named.toml last
        for f in b.files.iter().filter(|f| f.name != "named.toml") {
            fs::rename(stage.join(&f.name), dir.join(&f.name))
                .map_err(|e| format!("installing {}: {e}", f.name))?;
        }
        fs::rename(stage.join("named.toml"), dir.join("named.toml"))
            .map_err(|e| format!("installing named.toml: {e}"))?;
        // zone files that are no longer part of the bundle are moved aside, not deleted
        let keep: std::collections::HashSet<&str> =
            b.files.iter().map(|f| f.name.as_str()).collect();
        let orphans = dir.join(".orphaned");
        for e in fs::read_dir(dir).map_err(|e| e.to_string())?.flatten() {
            let n = e.file_name().to_string_lossy().to_string();
            if n.starts_with("zone.") && !n.ends_with(".tmp") && !keep.contains(n.as_str()) {
                let _ = fs::create_dir_all(&orphans);
                let _ = fs::rename(e.path(), orphans.join(format!("{n}.v{}", b.version)));
            }
        }
        write_synced(
            &dir.join(".agent_version"),
            b.version.to_string().as_bytes(),
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    })();
    let _ = fs::remove_dir_all(&stage);
    result
}

pub fn applied_version(dir: &Path) -> i64 {
    fs::read_to_string(dir.join(".agent_version"))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

#[derive(Serialize)]
struct Hello<'a> {
    id: &'a str,
    name: &'a str,
    addr: &'a str,
}

#[derive(Deserialize, Default)]
struct HeartbeatReply {
    #[serde(default)]
    desired_version: i64,
    #[serde(default)]
    sync_requested: bool,
}

struct Config {
    api: String,
    id: String,
    token: String,
    key: String,
    name: String,
    addr: String,
    dir: PathBuf,
    interval: Duration,
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

fn load_config() -> Result<Config, String> {
    let need = |n: &str| {
        env(n).ok_or_else(|| format!("{n} is required (register the agent in the dashboard first)"))
    };
    Ok(Config {
        api: env("CONTROL_API")
            .unwrap_or_else(|| "http://localhost:8080".into())
            .trim_end_matches('/')
            .to_string(),
        id: need("AGENT_ID")?,
        token: need("AGENT_TOKEN")?,
        key: need("AGENT_SIGNING_KEY")?,
        name: env("AGENT_NAME").unwrap_or_else(|| format!("agent-{}", std::process::id())),
        addr: need("AGENT_ADDR")?,
        dir: PathBuf::from(env("AGENT_ZONE_DIR").unwrap_or_else(|| "/etc/hickory".into())),
        interval: Duration::from_secs(
            env("HEARTBEAT_SECS")
                .and_then(|v| v.parse().ok())
                .unwrap_or(30)
                .max(5),
        ),
    })
}

async fn sync_once(c: &Config, http: &reqwest::Client, force: bool) -> Result<(), String> {
    let hb = http
        .post(format!("{}/api/v1/agents/heartbeat", c.api))
        .bearer_auth(&c.token)
        .json(&Hello {
            id: &c.id,
            name: &c.name,
            addr: &c.addr,
        })
        .send()
        .await
        .map_err(|e| format!("heartbeat failed: {e}"))?;
    if !hb.status().is_success() {
        return Err(format!("heartbeat rejected: HTTP {}", hb.status()));
    }
    let reply: HeartbeatReply = hb.json().await.unwrap_or_default();
    let have = applied_version(&c.dir);
    if !force && !reply.sync_requested && reply.desired_version <= have {
        return Ok(());
    }
    info!(
        "syncing: have v{have}, control plane wants v{} (requested: {})",
        reply.desired_version, reply.sync_requested
    );
    let res = http
        .get(format!("{}/api/v1/agents/{}/bundle", c.api, c.id))
        .bearer_auth(&c.token)
        .send()
        .await
        .map_err(|e| format!("bundle download failed: {e}"))?;
    if !res.status().is_success() {
        return Err(format!("bundle download rejected: HTTP {}", res.status()));
    }
    let bundle: Bundle = res
        .json()
        .await
        .map_err(|e| format!("bundle is not valid JSON: {e}"))?;
    let outcome = verify(&c.key, &bundle).and_then(|_| apply(&c.dir, &bundle));
    let ack = match &outcome {
        Ok(()) => serde_json::json!({"version": bundle.version, "ok": true}),
        Err(e) => serde_json::json!({"version": bundle.version, "ok": false, "error": e}),
    };
    if let Err(e) = http
        .post(format!("{}/api/v1/agents/{}/ack", c.api, c.id))
        .bearer_auth(&c.token)
        .json(&ack)
        .send()
        .await
    {
        warn!("could not acknowledge v{}: {e}", bundle.version);
    }
    outcome.map(|_| info!("applied bundle v{}", bundle.version))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let cfg = match load_config() {
        Ok(c) => c,
        Err(e) => {
            error!("{e}");
            std::process::exit(2);
        }
    };
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("http client");
    info!(
        "agent {} -> {} (zone dir {})",
        cfg.id,
        cfg.api,
        cfg.dir.display()
    );
    let mut first = true;
    loop {
        if let Err(e) = sync_once(&cfg, &http, first).await {
            error!("{e}");
        } else {
            first = false;
        }
        tokio::select! {
            _ = tokio::time::sleep(cfg.interval) => {}
            _ = tokio::signal::ctrl_c() => { info!("stopping"); return; }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files() -> Vec<BundleFile> {
        vec![
            BundleFile {
                name: "named.toml".into(),
                content: "zone_path = \"@ZONE_DIR@/zone.a.com\"\n".into(),
            },
            BundleFile {
                name: "zone.a.com".into(),
                content: "a.com. 3600 IN SOA ns. h. 1 1 1 1 1\n".into(),
            },
        ]
    }

    fn bundle(key: &str, version: i64) -> Bundle {
        let f = files();
        let hash = bundle_hash(&f);
        Bundle {
            version,
            signature: sign(key, version, &hash, &f),
            hash,
            files: f,
        }
    }

    #[test]
    fn matches_the_control_plane_test_vector() {
        // The same vector is asserted in control_api (ext::unit::agent_vector):
        // if either side changes the framing, both tests fail.
        let f = vec![
            BundleFile {
                name: "named.toml".into(),
                content: "x".into(),
            },
            BundleFile {
                name: "zone.a.com".into(),
                content: "y".into(),
            },
        ];
        let h = bundle_hash(&f);
        assert_eq!(
            h,
            "f21cd528f1ea6cec069650ce232d115707c5380f25699b0e11f8e43f50971c07"
        );
        assert_eq!(
            sign("k", 7, &h, &f),
            "7831a7e229049aab306a0414d7fc5dd327dcf16b39d118b196d00e4fa38c3213"
        );
    }

    #[test]
    fn valid_bundle_verifies_and_tampering_is_rejected() {
        let b = bundle("key", 3);
        assert!(verify("key", &b).is_ok());
        assert!(verify("other-key", &b).is_err(), "wrong key");
        let mut t = bundle("key", 3);
        t.files[1].content.push_str("evil. 1 IN A 6.6.6.6\n");
        assert!(verify("key", &t).is_err(), "content changed");
        let mut v = bundle("key", 3);
        v.version = 4;
        assert!(
            verify("key", &v).is_err(),
            "version changed (replay of an old bundle as a new one)"
        );
    }

    #[test]
    fn dangerous_file_names_are_refused() {
        for bad in [
            "../etc/passwd",
            "zone.a/../../x",
            "zone..x",
            "/abs",
            "evil.sh",
            "zone.a.tmp",
        ] {
            let f = vec![
                BundleFile {
                    name: "named.toml".into(),
                    content: "x".into(),
                },
                BundleFile {
                    name: bad.into(),
                    content: "y".into(),
                },
            ];
            let h = bundle_hash(&f);
            let b = Bundle {
                version: 1,
                signature: sign("k", 1, &h, &f),
                hash: h,
                files: f,
            };
            assert!(verify("k", &b).is_err(), "{bad}");
        }
    }

    #[test]
    fn apply_installs_atomically_and_rewrites_paths() {
        let d = tempfile::tempdir().unwrap();
        fs::write(d.path().join("zone.old.com"), "old").unwrap();
        fs::write(d.path().join("zone.a.com"), "previous").unwrap();
        apply(d.path(), &bundle("k", 5)).unwrap();
        let toml = fs::read_to_string(d.path().join("named.toml")).unwrap();
        assert!(
            toml.contains(&format!("{}/zone.a.com", d.path().to_string_lossy()))
                && !toml.contains(ZONE_DIR_TOKEN),
            "{toml}"
        );
        assert!(
            fs::read_to_string(d.path().join("zone.a.com"))
                .unwrap()
                .contains("SOA")
        );
        assert_eq!(applied_version(d.path()), 5);
        assert!(
            !d.path().join("zone.old.com").exists(),
            "zone no longer in the bundle is removed from service"
        );
        assert!(
            d.path().join(".orphaned").read_dir().unwrap().count() == 1,
            "...but kept for recovery"
        );
        assert!(!d.path().join(".staging-5").exists());
    }

    #[test]
    fn failed_apply_keeps_previous_files() {
        let d = tempfile::tempdir().unwrap();
        apply(d.path(), &bundle("k", 1)).unwrap();
        let before = fs::read_to_string(d.path().join("zone.a.com")).unwrap();
        // make staging impossible: a regular file where the staging directory must go
        fs::write(d.path().join(".staging-2"), "blocker").unwrap();
        // remove_dir_all fails on a file, create_dir_all then fails -> error before anything is replaced
        let mut b = bundle("k", 2);
        b.files[1].content = "changed".into();
        assert!(apply(d.path(), &b).is_err());
        assert_eq!(
            fs::read_to_string(d.path().join("zone.a.com")).unwrap(),
            before
        );
        assert_eq!(applied_version(d.path()), 1);
    }

    #[test]
    fn config_requires_credentials() {
        for v in ["AGENT_ID", "AGENT_TOKEN", "AGENT_SIGNING_KEY", "AGENT_ADDR"] {
            std::env::remove_var(v);
        }
        let e = load_config().err().unwrap();
        assert!(e.contains("AGENT_ID"), "{e}");
    }
}
