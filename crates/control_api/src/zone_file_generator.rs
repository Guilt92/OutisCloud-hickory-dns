use crate::db_pool::Pool;
use crate::dns_builder::{
    DnsRecordBuilder, SafeZoneFileWriter, TomlConfigBuilder, sync_parent_dir, write_synced,
};
use crate::dns_validator::validate_zone_file;
use anyhow::{Context, anyhow};
use hickory_proto::rr::domain::Name;
use log::{debug, error, info, warn};
use std::path::Path;
use std::sync::Arc;
use std::{
    collections::{HashMap, HashSet},
    fs,
};
use tokio::task;

/// Represents a single DNS record row fetched from the database.
#[derive(Clone, Debug)]
pub struct RecordRow {
    pub name: String,
    pub rtype: String,
    pub value: String,
    pub ttl: i32,
    pub priority: i32,
}

fn ensure_trailing_dot(s: &str) -> String {
    if s.ends_with('.') {
        s.to_string()
    } else {
        format!("{}.", s)
    }
}

fn fqdn_for_record(name: &str, domain: &str) -> String {
    let domain_base = domain.trim_end_matches('.');
    if name == "@" {
        ensure_trailing_dot(domain_base)
    } else if name.ends_with('.') {
        name.to_string()
    } else {
        let trimmed = name.trim_end_matches('.');
        // Users may supply the full hostname (e.g. "ns1.uid0.ir") instead of a
        // bare label (e.g. "www"). If the name already contains the zone domain
        // there is no need to append the origin a second time.
        if trimmed == domain_base || trimmed.ends_with(&format!(".{}", domain_base)) {
            ensure_trailing_dot(trimmed)
        } else {
            ensure_trailing_dot(&format!("{}.{}", trimmed, domain_base))
        }
    }
}

/// Convenience helper that reads the environment variable used to seed default
/// NS records when a zone lacks any. The value is expected to be a comma
/// separated list of FQDNs, for example "ns1.example.com.,ns2.example.com.".
/// This allows the configuration to be driven by the deployment environment
/// rather than hard-coding our own nameservers everywhere.
fn default_ns_records() -> Vec<String> {
    let env = std::env::var("PUBLIC_NAMESERVERS").unwrap_or_else(|_| {
        // backwards compatibility with older hardcoded defaults
        "ns1.my-dns.com.,ns2.my-dns.com.".to_string()
    });
    env.split(',')
        .filter(|s| !s.trim().is_empty())
        .map(|s| ensure_trailing_dot(s.trim()))
        .collect()
}

/// Internal generator that operates on already‑fetched zone/record data. This is
/// extracted so that unit tests can exercise the logic without requiring a live
/// Postgres instance.
pub struct GeoRuleRow {
    pub match_type: String,
    pub match_value: String,
    pub target: String,
    pub weight: u32,
    pub priority: i32,
    pub enabled: bool,
    pub record_name: Option<String>,
    pub record_type: Option<String>,
}

pub struct NameserverRow {
    pub hostname: String,
    pub ip_address: String,
    pub glue_ip: Option<String>,
    pub sort_order: i32,
    pub enabled: bool,
}

/// Outcome of one publication run.
#[derive(Debug, Default, Clone)]
pub struct PublishReport {
    /// Domains whose current zone file is the freshly generated one.
    pub published: Vec<String>,
    /// Domains that could not be (re)generated, with the reason. The previous
    /// zone file (last known-good) is left in place and still served.
    pub failed: Vec<(String, String)>,
}

impl PublishReport {
    pub fn is_ok(&self) -> bool {
        self.failed.is_empty()
    }
    pub fn error_for(&self, domain: &str) -> Option<&str> {
        let d = domain.trim_end_matches('.').to_ascii_lowercase();
        self.failed
            .iter()
            .find(|(z, _)| *z == d)
            .map(|(_, e)| e.as_str())
    }
}

fn effective_default_ns(nameservers: &[NameserverRow]) -> Vec<String> {
    if !nameservers.is_empty() {
        nameservers
            .iter()
            .filter(|ns| ns.enabled)
            .map(|ns| ensure_trailing_dot(&ns.hostname))
            .collect()
    } else {
        default_ns_records()
    }
}

/// First day-based serial: YYYYMMDD00.
fn today_serial() -> u32 {
    chrono::Utc::now()
        .format("%Y%m%d00")
        .to_string()
        .parse()
        .unwrap_or(1)
}

/// Rewrite the SOA line(s) so that the serial is `0` and fields are single-space
/// separated; used to decide whether a zone's content really changed.
fn normalize_for_compare(text: &str) -> String {
    text.lines()
        .map(|l| {
            let toks: Vec<&str> = l.split_whitespace().collect();
            if toks.len() >= 10 && toks[3] == "SOA" {
                let mut t: Vec<&str> = toks.clone();
                t[6] = "0";
                t.join(" ")
            } else {
                toks.join(" ")
            }
        })
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
pub fn __soa_serial_for_tests(text: &str) -> Option<u32> {
    soa_serial_in(text)
}

fn soa_serial_in(text: &str) -> Option<u32> {
    text.lines().find_map(|l| {
        let toks: Vec<&str> = l.split_whitespace().collect();
        if toks.len() >= 10 && toks[3] == "SOA" {
            toks[6].parse().ok()
        } else {
            None
        }
    })
}

/// Render the complete zone file text of one zone (no I/O).
///
/// `serial` overrides the SOA serial; `None` keeps the stored value. Returns the
/// text and the serial stored in the zone's own SOA row, if any.
pub fn render_zone(
    domain: &str,
    recs: &[RecordRow],
    nameservers: &[NameserverRow],
    serial: Option<u32>,
) -> anyhow::Result<(String, Option<u32>)> {
    let default_ns = effective_default_ns(nameservers);
    let domain_dot = ensure_trailing_dot(&domain.trim_end_matches('.').to_ascii_lowercase());
    let domain_base = domain_dot.trim_end_matches('.').to_string();
    let origin = Name::from_utf8(&domain_dot)
        .with_context(|| format!("Failed to parse origin for zone {}", domain_dot))?;

    // Determine if there is an SOA record in the dataset. Apex NS records
    // are not checked here: they are generated from the nameservers table
    // below, so any apex NS rows in the records table are skipped during
    // generation to avoid duplicates and stale values.
    let has_soa = recs.iter().any(|r| r.rtype.eq_ignore_ascii_case("SOA"));

    let mut zone_contents = String::new();
    let mut stored_serial: Option<u32> = None;

    // Add SOA record if not present. The primary nameserver (MNAME) is the
    // first enabled nameserver; fall back to ns1.<zone> only when none exist.
    if !has_soa {
        let mname = default_ns
            .first()
            .cloned()
            .unwrap_or_else(|| format!("ns1.{}", domain_dot));
        let soa_value = format!(
            "{} hostmaster.{} {} 3600 3600 604800 3600",
            mname,
            domain_dot,
            serial.unwrap_or_else(today_serial)
        );
        zone_contents.push_str(&format!("{} 3600 IN SOA {}\n", domain_dot, soa_value));
    }

    // owner name (lower-case fqdn) -> (has CNAME, has other data)
    let mut owners: HashMap<String, (usize, usize)> = HashMap::new();

    // Process each record - validation delegates entirely to Hickory DNS via DnsRecordBuilder
    let mut soa_emitted = false;
    for r in recs {
        // A zone may only carry a single SOA record. Zone creation already
        // inserts an apex SOA, so emitting every stored SOA row would
        // produce a zone file that Hickory's parser rejects ("SOA is
        // already specified"). Emit only the first SOA row.
        let is_soa = r.rtype.trim().eq_ignore_ascii_case("SOA");
        if is_soa {
            if soa_emitted {
                continue;
            }
            soa_emitted = true;
        }

        // Apex NS records are generated from the nameservers table below;
        // skip stored apex NS rows to avoid duplicates and stale values.
        // The apex matches both "@" and the bare zone domain itself
        // (e.g. "uid0.ir" or "uid0.ir."), not just subdomains.
        if r.rtype.trim().eq_ignore_ascii_case("NS") {
            let name_base = r.name.trim_end_matches('.').to_ascii_lowercase();
            if name_base == "@" || name_base == domain_base {
                continue;
            }
        }
        let fqdn = fqdn_for_record(&r.name, &domain_base);

        // The record must be inside this zone: an absolute name pointing
        // elsewhere would make the zone file claim data it is not
        // authoritative for.
        let fq_name = Name::from_utf8(&fqdn)
            .with_context(|| format!("Invalid record name '{}' in zone {}", r.name, domain_base))?;
        if !origin.zone_of(&fq_name) {
            return Err(anyhow!(
                "record name '{}' is outside zone '{}'",
                r.name,
                domain_base
            ));
        }

        // Build and validate record through Hickory DNS (from_db_fields calls validate internally)
        let record = DnsRecordBuilder::from_db_fields(
            fqdn.clone(),
            r.rtype.clone(),
            r.value.clone(),
            r.ttl,
            r.priority,
        )
        .with_context(|| {
            format!(
                "Invalid record in zone {}: {} {} {}",
                domain_base, fqdn, r.rtype, r.value
            )
        })?;

        if is_soa {
            stored_serial = record.soa_serial();
        }

        // CNAME may not coexist with other data at the same owner name
        // (RFC 1034 §3.6.2 / RFC 2181 §10.1). Hickory would otherwise serve a
        // zone with ambiguous answers.
        let entry = owners
            .entry(fq_name.to_ascii().to_ascii_lowercase())
            .or_insert((0, 0));
        if r.rtype.trim().eq_ignore_ascii_case("CNAME") {
            entry.0 += 1;
        } else {
            entry.1 += 1;
        }

        // Serialize to zone format using Hickory's Record::to_string().
        // The origin qualifier makes sure any relative domain name in the
        // RDATA (e.g. SOA mname/rname) is written fully-qualified so the
        // zone parser does not append the origin a second time.
        let text = record
            .to_zone_string_with_origin_and_serial(&origin, if is_soa { serial } else { None })
            .with_context(|| {
                format!(
                    "Failed to serialize record {} {} {} for zone {}",
                    fqdn, r.rtype, r.value, domain_base
                )
            })?;
        zone_contents.push_str(&text);
        zone_contents.push('\n');
    }

    for (owner, (cnames, other)) in &owners {
        if *cnames > 1 || (*cnames == 1 && *other > 0) {
            return Err(anyhow!(
                "CNAME conflict at '{}' in zone {}: a CNAME cannot coexist with other records (or another CNAME)",
                owner,
                domain_base
            ));
        }
        if *cnames > 0 && *owner == origin.to_ascii().to_ascii_lowercase() {
            return Err(anyhow!(
                "a CNAME cannot be placed at the zone apex ({})",
                domain_base
            ));
        }
    }

    // Nameserver (NS) records at the zone apex. The nameservers table is
    // the source of truth for the authoritative nameservers and applies to
    // every zone, so always emit the enabled ones here.
    for ns in &default_ns {
        zone_contents.push_str(&format!("{} 3600 IN NS {}\n", domain_dot, ns));
    }

    // Glue records: address records for nameserver hostnames that live inside
    // this zone (needed when the NS name is under the zone it serves).
    for ns_row in nameservers {
        if !ns_row.enabled {
            continue;
        }
        let ns_hostname = ns_row.hostname.trim_end_matches('.').to_ascii_lowercase();
        if ns_hostname != domain_base && ns_hostname.ends_with(&format!(".{}", domain_base)) {
            // The hostname is written fully-qualified: a relative name would
            // have the zone origin appended again by the zone parser.
            let ip = ns_row.ip_address.trim();
            match ip.parse::<std::net::IpAddr>() {
                Ok(std::net::IpAddr::V4(v4)) => {
                    zone_contents.push_str(&format!(
                        "{} 3600 IN A {}\n",
                        ensure_trailing_dot(&ns_hostname),
                        v4
                    ));
                }
                Ok(std::net::IpAddr::V6(v6)) => {
                    zone_contents.push_str(&format!(
                        "{} 3600 IN AAAA {}\n",
                        ensure_trailing_dot(&ns_hostname),
                        v6
                    ));
                }
                Err(_) => {
                    warn!(
                        "nameserver {} has an invalid IP address {:?}; glue omitted",
                        ns_hostname, ip
                    );
                }
            }
        }
    }

    Ok((zone_contents, stored_serial))
}

/// Validate (render + parse with Hickory) what a zone would look like, without
/// touching the disk. Used by the API to reject a change *before* it is saved.
pub fn precheck_zone(
    domain: &str,
    recs: &[RecordRow],
    nameservers: &[NameserverRow],
) -> anyhow::Result<()> {
    let (text, _) = render_zone(domain, recs, nameservers, Some(1))?;
    let domain_dot = ensure_trailing_dot(&domain.trim_end_matches('.').to_ascii_lowercase());
    let origin = Name::from_utf8(&domain_dot)?;
    validate_zone_file(Path::new("precheck"), &text, Some(&origin))
        .map_err(|e| anyhow!("{}", e))
        .with_context(|| format!("zone {} would not load", domain.trim_end_matches('.')))
}

/// Pick the serial for a new revision of a zone: strictly greater than the
/// serial of the currently published file whenever the content changed, never
/// lower than today's YYYYMMDD00 or than an operator-stored serial.
fn next_serial(prev_serial: Option<u32>, stored: Option<u32>, content_changed: bool) -> u32 {
    let floor = today_serial().max(stored.unwrap_or(0));
    match prev_serial {
        Some(p) if content_changed => floor.max(p.wrapping_add(1)),
        Some(p) => p.max(stored.unwrap_or(0)),
        None => floor,
    }
}

pub fn generate_from_data(
    base_dir: &str,
    zones: Vec<(String, String, bool)>, // (id, domain, geodns_enabled)
    records_map: HashMap<String, Vec<RecordRow>>,
    geo_rules_map: HashMap<String, Vec<GeoRuleRow>>,
    nameservers: Vec<NameserverRow>,
) -> anyhow::Result<PublishReport> {
    generate_with_ecs(
        base_dir,
        zones,
        &HashSet::new(),
        records_map,
        geo_rules_map,
        nameservers,
    )
}

/// Like [`generate_from_data`]; `ecs_zones` are the ids of zones that opted in
/// to EDNS Client Subnet aware geo decisions.
pub fn generate_with_ecs(
    base_dir: &str,
    zones: Vec<(String, String, bool)>, // (id, domain, geodns_enabled)
    ecs_zones: &HashSet<String>,
    records_map: HashMap<String, Vec<RecordRow>>, // key is zone_id
    geo_rules_map: HashMap<String, Vec<GeoRuleRow>>, // key is zone_id
    nameservers: Vec<NameserverRow>,              // nameservers from database
) -> anyhow::Result<PublishReport> {
    generate_full(
        base_dir,
        zones,
        ecs_zones,
        &HashMap::new(),
        records_map,
        geo_rules_map,
        nameservers,
    )
}

/// Like [`generate_with_ecs`]; `dnssec_keys` maps a zone id to its signing key
/// files `(absolute path, algorithm name)`. A signed zone never gets a GeoDNS
/// handler: synthesised per-client answers cannot carry a valid signature.
pub fn generate_full(
    base_dir: &str,
    zones: Vec<(String, String, bool)>,
    ecs_zones: &HashSet<String>,
    dnssec_keys: &HashMap<String, Vec<(String, String)>>,
    records_map: HashMap<String, Vec<RecordRow>>,
    geo_rules_map: HashMap<String, Vec<GeoRuleRow>>,
    nameservers: Vec<NameserverRow>,
) -> anyhow::Result<PublishReport> {
    generate_full_with_transfer_policies(
        base_dir,
        zones,
        ecs_zones,
        dnssec_keys,
        &HashMap::new(),
        &HashMap::new(),
        records_map,
        geo_rules_map,
        nameservers,
    )
}

/// Full publisher variant carrying the per-zone AXFR policy from persistent
/// control-plane state into the live Hickory server configuration.
pub fn generate_full_with_transfer_policies(
    base_dir: &str,
    zones: Vec<(String, String, bool)>,
    ecs_zones: &HashSet<String>,
    dnssec_keys: &HashMap<String, Vec<(String, String)>>,
    transfer_policies: &HashMap<String, String>,
    transfer_peers: &HashMap<String, Vec<String>>,
    records_map: HashMap<String, Vec<RecordRow>>,
    geo_rules_map: HashMap<String, Vec<GeoRuleRow>>,
    nameservers: Vec<NameserverRow>,
) -> anyhow::Result<PublishReport> {
    let base_path = Path::new(base_dir);
    std::fs::create_dir_all(base_path)
        .with_context(|| format!("failed to create dir {}", base_dir))?;

    let mut report = PublishReport::default();

    // make a set of names for zones we will generate so that we can clean up
    // files left over from previously deleted/renamed zones.
    let mut expected_files = HashSet::new();
    let mut seen_zone_files = HashSet::new();
    for (_id, domain, _enabled) in &zones {
        expected_files.insert(format!(
            "zone.{}",
            domain.trim_end_matches('.').to_ascii_lowercase()
        ));
    }

    // Build TOML configuration
    let mut toml_builder = TomlConfigBuilder::from_env();
    toml_builder.set_directory(base_dir);

    for (zone_id, domain, geodns_enabled) in &zones {
        let domain_norm = domain.trim_end_matches('.').to_ascii_lowercase();
        let zone_file_name = format!("zone.{}", domain_norm);
        let zone_path = base_path.join(&zone_file_name);

        // Two zones whose domains only differ by case or a trailing dot would
        // both write to the same zone file and the last one would silently
        // overwrite the other's records. The API normalizes domains, but guard
        // here as well so generation can never corrupt a zone file.
        if !seen_zone_files.insert(zone_file_name.clone()) {
            warn!(
                "skipping zone {}: another zone already maps to zone file {:?} (duplicate domain differing only by case or trailing dot?)",
                domain, zone_path
            );
            report
                .failed
                .push((domain_norm.clone(), "duplicate zone domain".to_string()));
            continue;
        }

        let recs = records_map.get(zone_id).cloned().unwrap_or_default();
        let domain_dot = ensure_trailing_dot(&domain_norm);

        // Each zone is generated in isolation: a problem in one tenant's data
        // must not stop other zones from being published, and must never
        // replace this zone's last known-good file with something broken.
        let result: anyhow::Result<bool> = (|| {
            let origin = Name::from_utf8(&domain_dot)
                .with_context(|| format!("Failed to parse origin for zone {}", domain_dot))?;

            // Pass 1: render with a neutral serial to learn whether the
            // content differs from what is currently published.
            let (probe, stored_serial) = render_zone(&domain_norm, &recs, &nameservers, Some(0))?;
            let prev = fs::read_to_string(&zone_path).ok();
            let (changed, prev_serial) = match &prev {
                Some(p) => (
                    normalize_for_compare(p) != normalize_for_compare(&probe),
                    soa_serial_in(p),
                ),
                None => (true, None),
            };
            let stored_newer = matches!((stored_serial, prev_serial), (Some(s), Some(p)) if s > p);
            if !changed && !stored_newer {
                debug!("zone {} unchanged; keeping published file", domain_norm);
                return Ok(false);
            }
            let serial = next_serial(prev_serial, stored_serial, changed || stored_newer);
            let (text, _) = render_zone(&domain_norm, &recs, &nameservers, Some(serial))?;

            // Write zone file with Hickory validation (final validation gate)
            debug!("Writing zone file for {}", domain_norm);
            SafeZoneFileWriter::write_validated(&zone_path, &text, Some(&origin)).with_context(|| {
                format!("Zone file validation failed for {}: Hickory parser rejected zone structure", domain_norm)
            })?;
            info!(
                "Successfully wrote zone file: {:?} (serial {})",
                zone_path, serial
            );
            Ok(true)
        })();

        match result {
            Ok(_) => report.published.push(domain_norm.clone()),
            Err(e) => {
                let msg = format!("{:#}", e);
                error!("zone {} was not published: {}", domain_norm, msg);
                report.failed.push((domain_norm.clone(), msg));
            }
        }

        // A zone is only added to the server configuration if a zone file
        // exists for it (the new one, or the last known-good one).
        if !zone_path.is_file() {
            continue;
        }
        let zone_path_str = zone_path.to_string_lossy().to_string();

        let geo_rules = if *geodns_enabled {
            geo_rules_map
                .get(zone_id)
                .map(|rules| {
                    rules
                        .iter()
                        .map(|rule| {
                            (
                                rule.match_type.clone(),
                                rule.match_value.clone(),
                                rule.target.clone(),
                                rule.weight,
                                rule.priority,
                                rule.enabled,
                                rule.record_name.clone(),
                                rule.record_type.clone(),
                            )
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        let keys = dnssec_keys.get(zone_id).cloned().unwrap_or_default();
        let geo_on = *geodns_enabled && keys.is_empty();
        toml_builder.add_zone(
            domain_norm.clone(),
            zone_path_str,
            geo_on,
            if geo_on { geo_rules } else { Vec::new() },
        )?;
        toml_builder.set_last_zone_ecs(ecs_zones.contains(zone_id) && geo_on);
        toml_builder.set_last_zone_keys(keys);
        toml_builder.set_last_zone_axfr_policy(
            transfer_policies
                .get(zone_id)
                .map(String::as_str)
                .unwrap_or("Deny"),
        );
        toml_builder
            .set_last_zone_transfer_peers(transfer_peers.get(zone_id).cloned().unwrap_or_default());
    }

    // Build and write TOML configuration (only if it changed, so an
    // unchanged zone set does not make the DNS server reload for nothing).
    let toml_content = toml_builder.build()?;
    let named_path = base_path.join("named.toml");
    if fs::read_to_string(&named_path)
        .map(|c| c == toml_content)
        .unwrap_or(false)
    {
        debug!("named.toml unchanged");
    } else {
        let tmp_named = base_path.join("named.toml.tmp");
        debug!(
            "Writing TOML configuration to temporary file: {:?}",
            tmp_named
        );
        // A stale temporary file (e.g. left behind by a previous run owned by a
        // different uid) would make the write fail. Remove it first so the
        // atomic tmp+rename pattern always works.
        let _ = fs::remove_file(&tmp_named);
        write_synced(&tmp_named, toml_content.as_bytes())
            .with_context(|| format!("failed to write named.toml temp at {:?}", tmp_named))?;
        fs::rename(&tmp_named, &named_path)
            .with_context(|| format!("failed to rename named.toml temp to {:?}", named_path))?;
        sync_parent_dir(&named_path);
    }

    // Only after the new configuration is live is it safe to quarantine zone
    // files that no longer belong to any zone. If the TOML write above failed,
    // the old files (still referenced by the old named.toml) stay untouched.
    let orphan_dir = base_path.join(".orphaned");
    for entry in fs::read_dir(base_path)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            if let Some(name) = entry.file_name().to_str() {
                if name.starts_with("zone.")
                    && !name.ends_with(".tmp")
                    && !expected_files.contains(name)
                {
                    debug!("Quarantining orphaned zone file: {}", name);
                    let _ = fs::create_dir_all(&orphan_dir);
                    let dest = orphan_dir.join(format!(
                        "{}.{}",
                        name,
                        chrono::Utc::now().format("%Y%m%d%H%M%S")
                    ));
                    if fs::rename(entry.path(), &dest).is_err() {
                        let _ = fs::remove_file(entry.path());
                    }
                }
            }
        }
    }

    if report.failed.is_empty() {
        info!("Successfully generated zone files and configuration");
    } else {
        warn!(
            "generated zone files with {} failed zone(s)",
            report.failed.len()
        );
    }
    Ok(report)
}

/// Fetch every zone, record, geo rule and nameserver. Any database error is
/// propagated: publishing from a partially-read (or empty) dataset would
/// delete or replace valid zones.
pub async fn load_nameservers(db: &Pool) -> anyhow::Result<Vec<NameserverRow>> {
    let ns_rows = db
        .query(
            "SELECT hostname, ip_address, glue_ip, sort_order, enabled FROM nameservers ORDER BY sort_order, hostname",
            &[],
        )
        .await
        .context("failed to read nameservers")?;
    Ok(ns_rows
        .into_iter()
        .map(|ns| NameserverRow {
            hostname: ns.get("hostname"),
            ip_address: ns.get("ip_address"),
            glue_ip: ns.get("glue_ip"),
            sort_order: ns.try_get("sort_order").unwrap_or(0),
            enabled: ns.try_get("enabled").unwrap_or(true),
        })
        .collect())
}

pub async fn load_zone_records(db: &Pool, zone_id: &str) -> anyhow::Result<Vec<RecordRow>> {
    let recs = db
        .query(
            "SELECT name, record_type, value, ttl, priority FROM records WHERE CAST(zone_id AS varchar) = $1 ORDER BY created_at, id",
            &[&zone_id],
        )
        .await
        .context("failed to read records")?;
    Ok(recs
        .into_iter()
        .map(|r| RecordRow {
            name: r.get("name"),
            rtype: r.get("record_type"),
            value: r.get("value"),
            ttl: r.try_get("ttl").unwrap_or(3600),
            priority: r.try_get("priority").unwrap_or(0),
        })
        .collect())
}

/// Generate all zone files and the named configuration directory by querying the
/// provided Postgres client.
pub async fn generate_all(
    base_dir: &str,
    db: Arc<crate::db_pool::Pool>,
) -> anyhow::Result<PublishReport> {
    let base = base_dir.to_string();

    let zones_rows = db
        .query("SELECT CAST(id AS varchar) AS id, domain, coalesce(geodns_enabled, true) AS geo, COALESCE(ecs_enabled, false) AS ecs, COALESCE(dnssec_enabled, false) AS signed, COALESCE(axfr_policy, 'Deny') AS axfr_policy, COALESCE(axfr_allowed_peers, '{}'::text[]) AS axfr_allowed_peers FROM zones WHERE COALESCE(status, 'active') IN ('active', 'held') ORDER BY domain", &[])
        .await
        .context("failed to read zones")?;

    let mut zones_vec = Vec::new();
    let mut ecs_zones: HashSet<String> = HashSet::new();
    let mut signed_zones: HashSet<String> = HashSet::new();
    let mut transfer_policies: HashMap<String, String> = HashMap::new();
    let mut transfer_peers: HashMap<String, Vec<String>> = HashMap::new();
    let mut records_map: HashMap<String, Vec<RecordRow>> = HashMap::new();
    let mut geo_rules_map: HashMap<String, Vec<GeoRuleRow>> = HashMap::new();

    for z in zones_rows {
        let zone_id: String = z.get("id");
        let domain: String = z.get("domain");
        let enabled: bool = z.get("geo");
        let signed: bool = z.get("signed");
        if signed && enabled {
            anyhow::bail!(
                "zone {} is both DNSSEC-signed and GeoDNS-enabled; refusing to publish an inconsistent configuration",
                domain
            );
        }
        if signed {
            signed_zones.insert(zone_id.clone());
        }
        if z.get::<_, bool>("ecs") {
            ecs_zones.insert(zone_id.clone());
        }
        transfer_policies.insert(zone_id.clone(), z.get("axfr_policy"));
        transfer_peers.insert(zone_id.clone(), z.get("axfr_allowed_peers"));
        zones_vec.push((zone_id.clone(), domain, enabled));
        records_map.insert(zone_id.clone(), Vec::new());
        geo_rules_map.insert(zone_id, Vec::new());
    }

    let record_rows = db
        .query(
            "SELECT CAST(r.zone_id AS varchar) AS zone_id, r.name, r.record_type, r.value, r.ttl, r.priority              FROM records r JOIN zones z ON z.id = r.zone_id              WHERE COALESCE(z.status, 'active') IN ('active', 'held') ORDER BY r.zone_id, r.created_at, r.id",
            &[],
        )
        .await
        .context("failed to read records")?;
    for r in record_rows {
        let zone_id: String = r.get("zone_id");
        if let Some(records) = records_map.get_mut(&zone_id) {
            records.push(RecordRow {
                name: r.get("name"),
                rtype: r.get("record_type"),
                value: r.get("value"),
                ttl: r.try_get("ttl").unwrap_or(3600),
                priority: r.try_get("priority").unwrap_or(0),
            });
        }
    }

    let geo_rows = db
        .query(
            "SELECT CAST(g.zone_id AS varchar) AS zone_id, g.match_type, g.match_value, g.target, g.priority, g.enabled, g.record_name, g.record_type, g.weight              FROM georules g JOIN zones z ON z.id = g.zone_id              WHERE COALESCE(z.status, 'active') IN ('active', 'held')              ORDER BY g.zone_id, g.priority DESC, g.match_type, g.match_value, g.target, g.id",
            &[],
        )
        .await
        .context("failed to read georules")?;
    for g in geo_rows {
        let zone_id: String = g.get("zone_id");
        if let Some(rules) = geo_rules_map.get_mut(&zone_id) {
            rules.push(GeoRuleRow {
                match_type: g.get("match_type"),
                match_value: g.get("match_value"),
                target: g.get("target"),
                priority: g.try_get("priority").unwrap_or(0),
                enabled: g.try_get("enabled").unwrap_or(true),
                record_name: g.try_get("record_name").unwrap_or(None),
                record_type: g.try_get("record_type").unwrap_or(None),
                weight: g.try_get::<_, i32>("weight").unwrap_or(1).max(0) as u32,
            });
        }
    }

    let nameservers = load_nameservers(&db).await?;
    // Fail closed: a key/database error must abort publication before any
    // file is touched. Publishing a signed zone without its keys would make
    // validators treat the zone as unsigned/bogus.
    let dnssec_keys = crate::dnssec::load_key_paths(&db, &base)
        .await
        .context("failed to load DNSSEC key metadata")?;
    for zone_id in &signed_zones {
        let keys = dnssec_keys
            .get(zone_id)
            .filter(|keys| !keys.is_empty())
            .ok_or_else(|| anyhow!("DNSSEC-enabled zone {} has no active signing key", zone_id))?;
        for (path, _algorithm) in keys {
            let contents = fs::read(path).with_context(|| {
                format!(
                    "cannot read DNSSEC key file {:?} for zone {}",
                    path, zone_id
                )
            })?;
            if contents.is_empty() {
                anyhow::bail!("DNSSEC key file {:?} for zone {} is empty", path, zone_id);
            }
        }
    }

    // blocking filesystem work off the async runtime
    task::spawn_blocking(move || {
        generate_full_with_transfer_policies(
            &base,
            zones_vec,
            &ecs_zones,
            &dnssec_keys,
            &transfer_policies,
            &transfer_peers,
            records_map,
            geo_rules_map,
            nameservers,
        )
    })
    .await?
}

// --------------------------------------------------------
// Unit tests for generator helpers and cleanup logic
// --------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_ensure_trailing_dot() {
        assert_eq!(ensure_trailing_dot("example"), "example.");
        assert_eq!(ensure_trailing_dot("example."), "example.");
    }

    #[test]
    fn test_fqdn_for_record() {
        assert_eq!(fqdn_for_record("@", "example.com"), "example.com.");
        assert_eq!(fqdn_for_record("www", "example.com"), "www.example.com.");
        assert_eq!(fqdn_for_record("www.", "example.com"), "www.");
        assert_eq!(fqdn_for_record("sub", "example.com."), "sub.example.com.");
        // full hostnames containing the zone domain must not be doubled
        assert_eq!(
            fqdn_for_record("ns1.example.com", "example.com"),
            "ns1.example.com."
        );
        assert_eq!(
            fqdn_for_record("ns1.example.com", "example.com."),
            "ns1.example.com."
        );
    }

    #[test]
    fn test_default_ns_records_env() {
        let previous = std::env::var("PUBLIC_NAMESERVERS").ok();
        std::env::remove_var("PUBLIC_NAMESERVERS");
        let defaults = default_ns_records();
        assert_eq!(
            defaults,
            vec!["ns1.my-dns.com.".to_string(), "ns2.my-dns.com.".to_string()]
        );
        std::env::set_var("PUBLIC_NAMESERVERS", "a.com.,b.com.");
        let custom = default_ns_records();
        assert_eq!(custom, vec!["a.com.".to_string(), "b.com.".to_string()]);
        // restore original
        if let Some(v) = previous {
            std::env::set_var("PUBLIC_NAMESERVERS", v);
        } else {
            std::env::remove_var("PUBLIC_NAMESERVERS");
        }
    }

    #[tokio::test]
    async fn test_generate_from_data_creates_and_removes() {
        let dir = tempdir().unwrap();
        let base = dir.path().to_str().unwrap();

        // create stale file that should be removed
        let stale = dir.path().join("zone.stale.com");
        fs::write(&stale, "garbage").unwrap();

        let zones = vec![("id1".to_string(), "example.com".to_string(), true)];
        let mut recs = HashMap::new();
        recs.insert(
            "id1".to_string(),
            vec![RecordRow {
                name: "@".into(),
                rtype: "A".into(),
                value: "1.2.3.4".into(),
                ttl: 3600,
                priority: 0,
            }],
        );
        let mut geo = HashMap::new();
        geo.insert(
            "id1".to_string(),
            vec![GeoRuleRow {
                match_type: "country".into(),
                match_value: "US".into(),
                target: "1.1.1.1".into(),
                weight: 7,
                priority: 1,
                enabled: true,
                record_name: None,
                record_type: None,
            }],
        );

        generate_from_data(base, zones, recs, geo, vec![]).unwrap();

        // stale file should be gone
        assert!(!stale.exists());

        // verify named.toml contains geodns section
        let named_path = dir.path().join("named.toml");
        let named_txt = fs::read_to_string(&named_path).unwrap();
        assert!(named_txt.contains("geodns"));
        assert!(named_txt.contains("weight = 7"));
        assert!(named_txt.contains("match_type"));
        assert!(named_txt.contains("US"));
    }

    #[tokio::test]
    async fn test_generate_from_data_geo_disabled() {
        let dir = tempdir().unwrap();
        let base = dir.path().to_str().unwrap();
        let zones = vec![("id1".to_string(), "example.com".to_string(), false)];
        let recs = HashMap::new();
        let geo = HashMap::new();
        generate_from_data(base, zones, recs, geo, vec![]).unwrap();
        let named_path = dir.path().join("named.toml");
        let named_txt = fs::read_to_string(&named_path).unwrap();
        assert!(!named_txt.contains("geodns"));
    }

    #[tokio::test]
    async fn test_generate_from_data_with_records() {
        let dir = tempdir().unwrap();
        let base = dir.path().to_str().unwrap();

        // create stale file that should be removed
        let stale = dir.path().join("zone.stale.com");
        fs::write(&stale, "garbage").unwrap();

        let zones = vec![("id1".to_string(), "example.com".to_string(), true)];
        let mut recs = HashMap::new();
        recs.insert(
            "id1".to_string(),
            vec![
                RecordRow {
                    name: "@".into(),
                    rtype: "A".into(),
                    value: "1.2.3.4".into(),
                    ttl: 3600,
                    priority: 0,
                },
                RecordRow {
                    name: "@".into(),
                    rtype: "MX".into(),
                    value: "mail.example.com.".into(),
                    ttl: 3600,
                    priority: 10,
                },
                RecordRow {
                    name: "_sip._tcp".into(),
                    rtype: "SRV".into(),
                    value: "target.example.com.".into(),
                    ttl: 3600,
                    priority: 20,
                },
            ],
        );
        let geo = HashMap::new();
        generate_from_data(base, zones, recs, geo, vec![]).unwrap();

        // stale file should be gone
        assert!(!stale.exists());

        // generated file should exist and contain the record
        let zonefile = dir.path().join("zone.example.com");
        assert!(zonefile.exists());
        let contents = fs::read_to_string(zonefile).unwrap();
        assert!(contents.contains("IN A 1.2.3.4"));
        // MX should have priority prefix
        assert!(contents.contains("IN MX 10 mail.example.com."));
        // SRV should have priority prefix followed by the weight, port, target
        assert!(contents.contains("IN SRV 20"));

        // named config should reference the zone
        let named = dir.path().join("named.toml");
        let named_contents = fs::read_to_string(named).unwrap();
        assert!(named_contents.contains("zone = \"example.com\""));
    }

    #[test]
    fn test_default_ns_and_soa_serial() {
        // isolate from other tests that may have set PUBLIC_NAMESERVERS
        let previous = std::env::var("PUBLIC_NAMESERVERS").ok();
        std::env::remove_var("PUBLIC_NAMESERVERS");

        let dir = tempdir().unwrap();
        let base = dir.path().to_str().unwrap();

        // no records provided -> defaults are added
        let zones = vec![("id1".to_string(), "example.com".to_string(), false)];
        let recs = HashMap::new();
        let geo = HashMap::new();
        generate_from_data(base, zones.clone(), recs, geo, vec![]).unwrap();

        let zonefile = dir.path().join("zone.example.com");
        let contents = fs::read_to_string(&zonefile).unwrap();
        assert!(contents.contains("IN NS ns1.my-dns.com."));
        assert!(contents.contains("IN NS ns2.my-dns.com."));

        // SOA line should have a numeric serial value
        let soa_line = contents.lines().find(|l| l.contains("SOA")).unwrap();
        let parts: Vec<&str> = soa_line.split_whitespace().collect();
        assert!(parts.len() >= 7); // fqdn ttl IN SOA mname rname serial...
        // Serial is at position 6: fqdn(0) ttl(1) IN(2) SOA(3) mname(4) rname(5) serial(6)
        let serial = parts[6];
        assert!(serial.chars().all(|c| c.is_digit(10)));

        // restore env var
        if let Some(v) = previous {
            std::env::set_var("PUBLIC_NAMESERVERS", v);
        }
    }

    #[tokio::test]
    async fn test_apex_ns_from_nameservers_table_with_glue() {
        let dir = tempdir().unwrap();
        let base = dir.path().to_str().unwrap();

        let zones = vec![("id1".to_string(), "example.com".to_string(), true)];
        // The records table holds a stale apex NS row; it must be replaced by
        // the nameservers from the nameservers table.
        let mut recs = HashMap::new();
        recs.insert(
            "id1".to_string(),
            vec![
                RecordRow {
                    name: "@".into(),
                    rtype: "NS".into(),
                    value: "ns1.stale.com.".into(),
                    ttl: 3600,
                    priority: 0,
                },
                RecordRow {
                    name: "www".into(),
                    rtype: "A".into(),
                    value: "1.2.3.4".into(),
                    ttl: 3600,
                    priority: 0,
                },
            ],
        );
        let geo = HashMap::new();
        let nameservers = vec![
            NameserverRow {
                hostname: "ns1.example.com.".into(),
                ip_address: "51.68.254.5".into(),
                glue_ip: None,
                sort_order: 0,
                enabled: true,
            },
            NameserverRow {
                hostname: "ns2.example.com.".into(),
                ip_address: "51.68.254.6".into(),
                glue_ip: None,
                sort_order: 1,
                enabled: true,
            },
        ];

        generate_from_data(base, zones, recs, geo, nameservers).unwrap();

        let zonefile = dir.path().join("zone.example.com");
        let contents = fs::read_to_string(&zonefile).unwrap();
        // Both nameservers are served at the apex; the stale one is gone.
        assert!(contents.contains("IN NS ns1.example.com."));
        assert!(contents.contains("IN NS ns2.example.com."));
        assert!(!contents.contains("ns1.stale.com"));
        // Glue A records for the in-zone nameserver hostnames (FQDN form).
        assert!(contents.contains("ns1.example.com. 3600 IN A 51.68.254.5"));
        assert!(contents.contains("ns2.example.com. 3600 IN A 51.68.254.6"));
        // Regular records are still present.
        assert!(contents.contains("IN A 1.2.3.4"));
    }

    #[test]
    fn test_duplicate_soa_rows_emit_only_one() {
        let dir = tempdir().unwrap();
        let base = dir.path().to_str().unwrap();

        let zones = vec![("id1".to_string(), "example.com".to_string(), true)];
        let mut recs = HashMap::new();
        recs.insert(
            "id1".to_string(),
            vec![
                RecordRow {
                    name: "@".into(),
                    rtype: "SOA".into(),
                    value:
                        "ns1.example.com hostmaster.example.com 2026010101 3600 3600 604800 3600"
                            .into(),
                    ttl: 3600,
                    priority: 0,
                },
                // second, stale SOA row (e.g. manually added after zone creation)
                RecordRow {
                    name: "@".into(),
                    rtype: "SOA".into(),
                    value:
                        "ns1.example.com. hostmaster.example.com. 2026010102 3600 3600 604800 3600"
                            .into(),
                    ttl: 3600,
                    priority: 0,
                },
            ],
        );
        let geo = HashMap::new();

        generate_from_data(base, zones, recs, geo, vec![]).unwrap();

        let zonefile = dir.path().join("zone.example.com");
        let contents = fs::read_to_string(&zonefile).unwrap();
        // only one SOA line may ever be emitted (Hickory rejects duplicates)
        let soa_count = contents.lines().filter(|l| l.contains("IN SOA")).count();
        assert_eq!(
            soa_count, 1,
            "expected exactly one SOA line, got:\n{}",
            contents
        );
    }

    #[test]
    fn test_apex_ns_skipped_by_domain_name() {
        let dir = tempdir().unwrap();
        let base = dir.path().to_str().unwrap();

        let zones = vec![("id1".to_string(), "example.com".to_string(), false)];
        let mut recs = HashMap::new();
        recs.insert(
            "id1".to_string(),
            vec![
                // apex NS stored as the bare zone domain (not "@")
                RecordRow {
                    name: "example.com".into(),
                    rtype: "NS".into(),
                    value: "ns1.stale.com.".into(),
                    ttl: 3600,
                    priority: 0,
                },
                RecordRow {
                    name: "example.com.".into(),
                    rtype: "NS".into(),
                    value: "ns2.stale.com.".into(),
                    ttl: 3600,
                    priority: 0,
                },
                // a real subdomain NS must NOT be skipped
                RecordRow {
                    name: "sub".into(),
                    rtype: "NS".into(),
                    value: "ns3.stale.com.".into(),
                    ttl: 3600,
                    priority: 0,
                },
            ],
        );
        let geo = HashMap::new();
        let nameservers = vec![NameserverRow {
            hostname: "ns1.example.com.".into(),
            ip_address: "51.68.254.5".into(),
            glue_ip: None,
            sort_order: 0,
            enabled: true,
        }];

        generate_from_data(base, zones, recs, geo, nameservers).unwrap();

        let zonefile = dir.path().join("zone.example.com");
        let contents = fs::read_to_string(&zonefile).unwrap();
        // apex NS comes only from the nameservers table
        assert!(contents.contains("IN NS ns1.example.com."));
        assert!(!contents.contains("ns1.stale.com"));
        assert!(!contents.contains("ns2.stale.com"));
        // subdomain NS record is preserved
        assert!(
            contents.contains("sub.example.com. 3600 IN NS ns3.stale.com."),
            "was:\n{}",
            contents
        );
    }

    fn rec(name: &str, t: &str, v: &str) -> RecordRow {
        RecordRow {
            name: name.into(),
            rtype: t.into(),
            value: v.into(),
            ttl: 300,
            priority: 0,
        }
    }

    fn one_zone(dir: &str, recs: Vec<RecordRow>) -> PublishReport {
        let zones = vec![("id1".to_string(), "example.com".to_string(), false)];
        let mut m = HashMap::new();
        m.insert("id1".to_string(), recs);
        generate_from_data(dir, zones, m, HashMap::new(), vec![]).unwrap()
    }

    #[test]
    fn serial_is_monotonic_and_only_moves_on_change() {
        let dir = tempdir().unwrap();
        let b = dir.path().to_str().unwrap();
        let zf = dir.path().join("zone.example.com");
        one_zone(b, vec![rec("www", "A", "192.0.2.1")]);
        let s1 = soa_serial_in(&fs::read_to_string(&zf).unwrap()).unwrap();
        one_zone(b, vec![rec("www", "A", "192.0.2.1")]);
        assert_eq!(
            soa_serial_in(&fs::read_to_string(&zf).unwrap()).unwrap(),
            s1,
            "no change, no bump"
        );
        one_zone(b, vec![rec("www", "A", "192.0.2.2")]);
        let s2 = soa_serial_in(&fs::read_to_string(&zf).unwrap()).unwrap();
        assert!(s2 > s1);
        one_zone(b, vec![rec("www", "A", "192.0.2.3")]);
        let s3 = soa_serial_in(&fs::read_to_string(&zf).unwrap()).unwrap();
        assert!(s3 > s2, "{s3} {s2}");
    }

    #[test]
    fn serial_never_goes_backwards_past_an_existing_higher_serial() {
        let dir = tempdir().unwrap();
        let b = dir.path().to_str().unwrap();
        let zf = dir.path().join("zone.example.com");
        // a zone published earlier with a far-future serial
        one_zone(b, vec![rec("www", "A", "192.0.2.1")]);
        let text = fs::read_to_string(&zf).unwrap().replace(
            &soa_serial_in(&fs::read_to_string(&zf).unwrap())
                .unwrap()
                .to_string(),
            "4000000000",
        );
        fs::write(&zf, text).unwrap();
        one_zone(b, vec![rec("www", "A", "192.0.2.9")]);
        assert_eq!(
            soa_serial_in(&fs::read_to_string(&zf).unwrap()).unwrap(),
            4000000001
        );
    }

    #[test]
    fn failing_zone_keeps_last_known_good_and_does_not_stop_others() {
        let dir = tempdir().unwrap();
        let b = dir.path().to_str().unwrap();
        let zones = vec![
            ("a".to_string(), "a.example".to_string(), false),
            ("b".to_string(), "b.example".to_string(), false),
        ];
        let mut m = HashMap::new();
        m.insert("a".to_string(), vec![rec("www", "A", "192.0.2.1")]);
        m.insert("b".to_string(), vec![rec("www", "A", "192.0.2.2")]);
        generate_from_data(b, zones.clone(), m.clone(), HashMap::new(), vec![]).unwrap();
        let a_before = fs::read_to_string(dir.path().join("zone.a.example")).unwrap();

        // zone a gets invalid data, zone b a legitimate change
        m.insert("a".to_string(), vec![rec("www", "A", "not-an-ip")]);
        m.insert("b".to_string(), vec![rec("www", "A", "192.0.2.22")]);
        let report = generate_from_data(b, zones, m, HashMap::new(), vec![]).unwrap();
        assert_eq!(report.failed.len(), 1);
        assert_eq!(report.failed[0].0, "a.example");
        assert_eq!(
            fs::read_to_string(dir.path().join("zone.a.example")).unwrap(),
            a_before
        );
        assert!(
            fs::read_to_string(dir.path().join("zone.b.example"))
                .unwrap()
                .contains("192.0.2.22")
        );
        let named = fs::read_to_string(dir.path().join("named.toml")).unwrap();
        assert!(named.contains("a.example") && named.contains("b.example"));
        assert!(!dir.path().join("zone.a.example.tmp").exists());
    }

    #[test]
    fn brand_new_zone_that_fails_is_not_configured() {
        let dir = tempdir().unwrap();
        let report = one_zone(dir.path().to_str().unwrap(), vec![rec("www", "A", "bogus")]);
        assert_eq!(report.failed.len(), 1);
        assert!(!dir.path().join("zone.example.com").exists());
        assert!(
            !fs::read_to_string(dir.path().join("named.toml"))
                .unwrap()
                .contains("example.com")
        );
    }

    #[test]
    fn orphaned_zone_files_are_quarantined_not_deleted() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("zone.gone.com"), "x").unwrap();
        generate_from_data(
            dir.path().to_str().unwrap(),
            vec![],
            HashMap::new(),
            HashMap::new(),
            vec![],
        )
        .unwrap();
        assert!(!dir.path().join("zone.gone.com").exists());
        let kept: Vec<_> = fs::read_dir(dir.path().join(".orphaned"))
            .unwrap()
            .collect();
        assert_eq!(kept.len(), 1);
    }

    #[test]
    fn cname_conflicts_and_foreign_names_are_rejected() {
        let ns: Vec<NameserverRow> = vec![];
        assert!(
            precheck_zone(
                "example.com",
                &[
                    rec("www", "CNAME", "a.example.com."),
                    rec("www", "A", "192.0.2.1")
                ],
                &ns
            )
            .is_err()
        );
        assert!(
            precheck_zone(
                "example.com",
                &[
                    rec("www", "CNAME", "a.example.com."),
                    rec("www", "CNAME", "b.example.com.")
                ],
                &ns
            )
            .is_err()
        );
        assert!(precheck_zone("example.com", &[rec("@", "CNAME", "a.example.com.")], &ns).is_err());
        assert!(
            precheck_zone("example.com", &[rec("x.other.org.", "A", "192.0.2.1")], &ns).is_err()
        );
        assert!(
            precheck_zone(
                "example.com",
                &[
                    rec("a", "CNAME", "b.example.org."),
                    rec("b", "A", "192.0.2.1")
                ],
                &ns
            )
            .is_ok()
        );
    }

    #[test]
    fn ipv6_nameserver_gets_aaaa_glue_and_bad_ip_is_skipped() {
        let ns = vec![
            NameserverRow {
                hostname: "ns1.example.com".into(),
                ip_address: "2001:db8::53".into(),
                glue_ip: None,
                sort_order: 0,
                enabled: true,
            },
            NameserverRow {
                hostname: "ns2.example.com".into(),
                ip_address: "garbage".into(),
                glue_ip: None,
                sort_order: 1,
                enabled: true,
            },
        ];
        let (text, _) = render_zone("example.com", &[], &ns, Some(1)).unwrap();
        assert!(
            text.contains("ns1.example.com. 3600 IN AAAA 2001:db8::53"),
            "{text}"
        );
        assert!(!text.contains("garbage"), "{text}");
        // MNAME of the default SOA is a real nameserver
        assert!(
            text.contains("SOA ns1.example.com. hostmaster.example.com."),
            "{text}"
        );
    }

    #[test]
    fn mixed_case_domain_maps_to_one_lowercase_file() {
        let dir = tempdir().unwrap();
        let zones = vec![("id1".to_string(), "Example.COM".to_string(), false)];
        generate_from_data(
            dir.path().to_str().unwrap(),
            zones,
            HashMap::new(),
            HashMap::new(),
            vec![],
        )
        .unwrap();
        assert!(dir.path().join("zone.example.com").is_file());
    }
}
