use anyhow::Context;
use std::sync::Arc;
use tokio_postgres::Client;
use std::path::Path;
use std::{collections::{HashSet, HashMap}, fs};
use tokio::task;
use log::{debug, warn, info};
use hickory_proto::rr::domain::Name;
use crate::dns_builder::{DnsRecordBuilder, SafeZoneFileWriter, TomlConfigBuilder};
use crate::dns_validator::{validate_zone_has_soa, validate_zone_has_ns};

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
    if s.ends_with('.') { s.to_string() } else { format!("{}.", s) }
}

fn fqdn_for_record(name: &str, domain: &str) -> String {
    let domain_base = domain.trim_end_matches('.');
    if name == "@" {
        ensure_trailing_dot(domain_base)
    } else if name.ends_with('.') {
        name.to_string()
    } else {
        ensure_trailing_dot(&format!("{}.{}", name.trim_end_matches('.'), domain_base))
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

pub fn generate_from_data(
    base_dir: &str,
    zones: Vec<(String, String, bool)>, // (id, domain, geodns_enabled)
    records_map: HashMap<String, Vec<RecordRow>>, // key is zone_id
    geo_rules_map: HashMap<String, Vec<GeoRuleRow>>, // key is zone_id
    nameservers: Vec<NameserverRow>, // nameservers from database
) -> anyhow::Result<()> {
    let base_path = Path::new(base_dir);
    std::fs::create_dir_all(base_path).with_context(|| format!("failed to create dir {}", base_dir))?;

    // make a set of names for zones we will generate so that we can clean up
    // files left over from previously deleted/renamed zones.
    let mut expected_files = HashSet::new();
    for (_id, domain, _enabled) in &zones {
        expected_files.insert(format!("zone.{}", domain.trim_end_matches('.')));
    }

    // Build TOML configuration
    let mut toml_builder = TomlConfigBuilder::new();

    // Use provided nameservers from database, or fall back to environment variable
    let default_ns: Vec<String> = if !nameservers.is_empty() {
        nameservers.iter()
            .filter(|ns| ns.enabled)
            .map(|ns| ensure_trailing_dot(&ns.hostname))
            .collect()
    } else {
        default_ns_records()
    };

    for (zone_id, domain, geodns_enabled) in &zones {
        let zone_file_name = format!("zone.{}", domain.trim_end_matches('.'));
        let zone_path = base_path.join(&zone_file_name);

        let recs = records_map.get(zone_id).cloned().unwrap_or_default();
        let domain_dot = ensure_trailing_dot(domain.trim_end_matches('.'));

        // Determine if there is an SOA and NS record in the dataset
        let mut has_soa = false;
        let mut has_ns = false;
        for r in &recs {
            match r.rtype.to_uppercase().as_str() {
                "SOA" => has_soa = true,
                "NS" => has_ns = true,
                _ => {}
            }
        }

        // Build zone content using the DNS builder
        let mut zone_contents = String::new();

        // Add SOA record if not present
        if !has_soa {
            let serial = chrono::Utc::now().format("%Y%m%d00").to_string();
            let soa_value = format!(
                "ns1.{} hostmaster.{} {} 3600 3600 604800 3600",
                domain_dot, domain_dot, serial
            );

            // Write the default SOA record directly - format validation happens at zone file write time
            zone_contents.push_str(&format!("{} 3600 IN SOA {}\n", domain_dot, soa_value));
        }

        // Process each record from the database, validating through Hickory
        for r in recs {
            let fqdn = fqdn_for_record(&r.name, &domain);

            // Build and validate record through Hickory DNS APIs (fail-fast on invalid)
            match DnsRecordBuilder::from_db_fields(
                fqdn.clone(),
                r.rtype.clone(),
                r.value.clone(),
                r.ttl,
                r.priority,
            ) {
                Ok(record) => {
                    // Validate the record - this delegates to Hickory
                    if let Err(e) = record.validate() {
                        return Err(anyhow!(
                            "Invalid record in zone {}: {} {} {} - {}",
                            domain, fqdn, r.ttl, r.rtype, e
                        ));
                    }

                    // Convert to zone file format (delegates to Hickory Record::to_string())
                    match record.to_zone_string() {
                        Ok(text) => {
                            zone_contents.push_str(&text);
                            zone_contents.push('\n');
                        }
                        Err(e) => {
                            return Err(anyhow!(
                                "Failed to serialize record {} {} {} for zone {} - {}",
                                fqdn, r.rtype, r.value, domain, e
                            ));
                        }
                    }
                }
                Err(e) => {
                    return Err(anyhow!(
                        "Invalid record in zone {}: {}: type={} value={} - {}",
                        domain, fqdn, r.rtype, r.value, e
                    ));
                }
            }
        }

        // Add default NS records if none exist
        if !has_ns {
            for ns in &default_ns {
                zone_contents.push_str(&format!("{} 3600 IN NS {}\n", domain_dot, ns));
            }
        }

        // Write zone file with Hickory validation (final validation gate)
        debug!("Writing zone file for {}", domain);
        let origin = Name::from_utf8(&domain_dot)
            .with_context(|| format!("Failed to parse origin for zone {}", domain_dot))?;
        SafeZoneFileWriter::write_validated(&zone_path, &zone_contents, Some(&origin))
            .with_context(|| format!("Zone file validation failed for {}: Hickory parser rejected zone structure", domain))?;

        info!("Successfully wrote zone file: {:?}", zone_path);

        // Add zone to TOML configuration
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

        toml_builder.add_zone(domain.to_string(), zone_path_str, *geodns_enabled, geo_rules)?;
    }

    // cleanup any leftover zone files that are no longer present in the DB
    for entry in fs::read_dir(base_path)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            if let Some(name) = entry.file_name().to_str() {
                if name.starts_with("zone.") && !expected_files.contains(name) {
                    debug!("Removing orphaned zone file: {}", name);
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
    }

    // Build and write TOML configuration
    let toml_content = toml_builder.build()?;
    let named_path = base_path.join("named.toml");
    let tmp_named = base_path.join("named.toml.tmp");

    debug!("Writing TOML configuration to temporary file: {:?}", tmp_named);
    fs::write(&tmp_named, &toml_content).with_context(|| format!("failed to write named.toml temp at {:?}", tmp_named))?;

    debug!("Moving TOML configuration to final location: {:?}", named_path);
    fs::rename(&tmp_named, &named_path).with_context(|| format!("failed to rename named.toml temp to {:?}", named_path))?;

    info!("Successfully generated zone files and configuration");
    Ok(())
}

/// Generate all zone files and the named configuration directory by querying the
/// provided Postgres client.
pub async fn generate_all(base_dir: &str, db: Arc<Client>) -> anyhow::Result<()> {
    let base = base_dir.to_string();
    let db = db.clone();

    // do blocking FS work in a spawn_blocking
    task::spawn_blocking(move || -> anyhow::Result<()> {
        // use a tiny runtime so we can call async pg queries from sync context
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        let (zones, records_map, geo_rules_map, nameservers) = rt.block_on(async move {
            let zones_rows = db
                .query("SELECT CAST(id AS varchar), domain, coalesce(geodns_enabled, true) FROM zones", &[])
                .await
                .unwrap_or_default();

            let mut zones_vec = Vec::new();
            let mut records_map: HashMap<String, Vec<RecordRow>> = HashMap::new();
            let mut geo_rules_map: HashMap<String, Vec<GeoRuleRow>> = HashMap::new();

            for z in zones_rows {
                let zone_id: String = z.try_get("id").unwrap_or_default();
                let domain: String = z.try_get("domain").unwrap_or_default();
                let enabled: bool = z.try_get(2).unwrap_or(true);
                zones_vec.push((zone_id.clone(), domain, enabled));

                let recs = db
                    .query(
                        "SELECT name, type, value, ttl, priority FROM records WHERE CAST(zone_id AS varchar) = $1",
                        &[&zone_id],
                    )
                    .await
                    .unwrap_or_default();

                let mut list = Vec::new();
                for r in recs {
                    list.push(RecordRow {
                        name: r.try_get("name").unwrap_or_default(),
                        rtype: r.try_get("type").unwrap_or_default(),
                        value: r.try_get("value").unwrap_or_default(),
                        ttl: r.try_get("ttl").unwrap_or(3600),
                        priority: r.try_get("priority").unwrap_or(0),
                    });
                }
                records_map.insert(zone_id.clone(), list);

                // fetch georules for this zone
                let geos = db
                    .query(
                        "SELECT match_type, match_value, target, priority, enabled, record_name, record_type FROM georules WHERE CAST(zone_id AS varchar) = $1",
                        &[&zone_id],
                    )
                    .await
                    .unwrap_or_default();

                let mut geo_list = Vec::new();
                for g in geos {
                    geo_list.push(GeoRuleRow {
                        match_type: g.try_get("match_type").unwrap_or_default(),
                        match_value: g.try_get("match_value").unwrap_or_default(),
                        target: g.try_get("target").unwrap_or_default(),
                        priority: g.try_get("priority").unwrap_or(0),
                        enabled: g.try_get("enabled").unwrap_or(true),
                        record_name: g.try_get("record_name").unwrap_or(None),
                        record_type: g.try_get("record_type").unwrap_or(None),
                    });
                }
                geo_rules_map.insert(zone_id, geo_list);
            }

            // Fetch nameservers from database
            let ns_rows = db
                .query("SELECT hostname, ip_address, glue_ip, sort_order, enabled FROM nameservers ORDER BY sort_order, hostname", &[])
                .await
                .unwrap_or_default();

            let mut nameservers = Vec::new();
            for ns in ns_rows {
                nameservers.push(NameserverRow {
                    hostname: ns.try_get("hostname").unwrap_or_default(),
                    ip_address: ns.try_get("ip_address").unwrap_or_default(),
                    glue_ip: ns.try_get("glue_ip").ok(),
                    sort_order: ns.try_get("sort_order").unwrap_or(0),
                    enabled: ns.try_get("enabled").unwrap_or(true),
                });
            }

            (zones_vec, records_map, geo_rules_map, nameservers)
        });

        // perform file system work using the pure-data helper
        generate_from_data(&base, zones, records_map, geo_rules_map, nameservers)
    })
    .await??;

    Ok(())
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
    }

    #[test]
    fn test_default_ns_records_env() {
        std::env::remove_var("PUBLIC_NAMESERVERS");
        let defaults = default_ns_records();
        assert_eq!(
            defaults,
            vec!["ns1.my-dns.com.".to_string(), "ns2.my-dns.com.".to_string()]
        );
        std::env::set_var("PUBLIC_NAMESERVERS", "a.com.,b.com.");
        let custom = default_ns_records();
        assert_eq!(custom, vec!["a.com.".to_string(), "b.com.".to_string()]);
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
            vec![
                RecordRow {
                    name: "@".into(),
                    rtype: "A".into(),
                    value: "1.2.3.4".into(),
                    ttl: 3600,
                    priority: 0,
                },
            ],
        );
        let mut geo = HashMap::new();
        geo.insert(
            "id1".to_string(),
            vec![GeoRuleRow {
                match_type: "country".into(),
                match_value: "US".into(),
                target: "1.1.1.1".into(),
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
        assert!(parts.len() >= 7);  // fqdn ttl IN SOA mname rname serial...
        // Serial is at position 6: fqdn(0) ttl(1) IN(2) SOA(3) mname(4) rname(5) serial(6)
        let serial = parts[6];
        assert!(serial.chars().all(|c| c.is_digit(10)));
    }
}
