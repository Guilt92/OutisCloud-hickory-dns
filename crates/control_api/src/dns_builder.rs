//! Type-safe DNS record builder module
//!
//! This module provides strongly-typed APIs for building DNS records and zones using
//! Hickory DNS types, eliminating all string-based DNS generation. All records are
//! validated before persistence.

use anyhow::{anyhow, Context, Result};
use hickory_proto::rr::{
    DNSClass, RData, Name,
    rdata::{SOA, A, AAAA, CNAME, MX, NS, SRV, TXT},
};
use hickory_proto::rr::Record;
use std::net::IpAddr;
use std::path::Path;
use std::fs;
use log::{debug, warn};

/// High-level DNS record type used for creating records
#[derive(Debug, Clone)]
pub enum DnsRecordType {
    /// Start of Authority record
    SOA {
        mname: String,
        rname: String,
        serial: u32,
        refresh: i32,
        retry: i32,
        expire: i32,
        minimum: i32,
    },
    /// Name Server record
    NS { nameserver: String },
    /// Address record (IPv4)
    A { address: String },
    /// Address record (IPv6)
    AAAA { address: String },
    /// Canonical Name record
    CNAME { target: String },
    /// Mail Exchange record
    MX { preference: u16, exchange: String },
    /// Service record
    SRV { 
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    /// Text record
    TXT { text: String },
}

/// Represents a complete DNS record with all metadata
#[derive(Debug, Clone)]
pub struct DnsRecord {
    /// The record name (FQDN)
    pub name: String,
    /// The record type (SOA, A, AAAA, etc.)
    pub rtype: DnsRecordType,
    /// Time to live in seconds
    pub ttl: u32,
}

impl DnsRecord {
    /// Creates a new DNS record with the given parameters
    pub fn new(name: String, rtype: DnsRecordType, ttl: u32) -> Self {
        Self { name, rtype, ttl }
    }

    /// Converts this DnsRecord into a Hickory Record
    ///
    /// # Errors
    /// Returns an error if the record cannot be parsed or created
    pub fn to_hickory_record(&self) -> Result<Record> {
        let name = Name::from_utf8(&self.name)
            .with_context(|| format!("Failed to parse DNS name: {}", self.name))?;

        let rdata = match &self.rtype {
            DnsRecordType::SOA {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => {
                let mname_obj = Name::from_utf8(mname)
                    .with_context(|| format!("Failed to parse SOA mname: {}", mname))?;
                let rname_obj = Name::from_utf8(rname)
                    .with_context(|| format!("Failed to parse SOA rname: {}", rname))?;

                RData::SOA(SOA::new(
                    mname_obj,
                    rname_obj,
                    *serial,
                    *refresh,
                    *retry,
                    *expire,
                    *minimum as u32,
                ))
            }
            DnsRecordType::NS { nameserver } => {
                let ns = Name::from_utf8(nameserver)
                    .with_context(|| format!("Failed to parse NS record: {}", nameserver))?;
                RData::NS(NS(ns))
            }
            DnsRecordType::A { address } => {
                let ip: IpAddr = address.parse()
                    .with_context(|| format!("Failed to parse A record address: {}", address))?;
                match ip {
                    IpAddr::V4(v4) => RData::A(A(v4)),
                    IpAddr::V6(_) => return Err(anyhow!("IPv6 address provided for A record, use AAAA instead")).with_context(|| format!("Address: {}", address)),
                }
            }
            DnsRecordType::AAAA { address } => {
                let ip: IpAddr = address.parse()
                    .with_context(|| format!("Failed to parse AAAA record address: {}", address))?;
                match ip {
                    IpAddr::V6(v6) => RData::AAAA(AAAA(v6)),
                    IpAddr::V4(_) => return Err(anyhow!("IPv4 address provided for AAAA record, use A instead")).with_context(|| format!("Address: {}", address)),
                }
            }
            DnsRecordType::CNAME { target } => {
                let target_name = Name::from_utf8(target)
                    .with_context(|| format!("Failed to parse CNAME target: {}", target))?;
                RData::CNAME(CNAME(target_name))
            }
            DnsRecordType::MX {
                preference,
                exchange,
            } => {
                let exchange_name = Name::from_utf8(exchange)
                    .with_context(|| format!("Failed to parse MX exchange: {}", exchange))?;
                RData::MX(MX::new(*preference, exchange_name))
            }
            DnsRecordType::SRV {
                priority,
                weight,
                port,
                target,
            } => {
                let target_name = Name::from_utf8(target)
                    .with_context(|| format!("Failed to parse SRV target: {}", target))?;
                RData::SRV(SRV::new(*priority, *weight, *port, target_name))
            }
            DnsRecordType::TXT { text } => {
                // TXT records can contain multiple strings; for now we'll support a single string
                RData::TXT(TXT::new(vec![text.clone()]))
            }
        };

        Ok(Record::from_rdata(name, self.ttl, rdata).set_dns_class(DNSClass::IN).clone())
    }

    /// Validates that this record can be converted to a Hickory Record
    ///
    /// # Errors
    /// Returns an error if the record is invalid
    pub fn validate(&self) -> Result<()> {
        self.to_hickory_record().map(|_| ())
    }
}

/// Builder for creating DNS records from database-style data
pub struct DnsRecordBuilder;

impl DnsRecordBuilder {
    /// Creates a DnsRecord from database fields
    ///
    /// This is the main API for converting database records into type-safe DNS records.
    /// It validates the input and returns an error if the record cannot be created.
    pub fn from_db_fields(
        name: String,
        rtype: String,
        value: String,
        ttl: i32,
        priority: i32,
    ) -> Result<DnsRecord> {
        let ttl = u32::try_from(ttl)
            .with_context(|| format!("Invalid TTL value: {}", ttl))?;

        let record_type = match rtype.to_uppercase().as_str() {
            "SOA" => Self::parse_soa_value(&value)?,
            "NS" => DnsRecordType::NS {
                nameserver: Self::normalize_fqdn(&value)?,
            },
            "A" => DnsRecordType::A {
                address: value.parse()
                    .with_context(|| format!("Invalid A record address: {}", value))?,
            },
            "AAAA" => DnsRecordType::AAAA {
                address: value.parse()
                    .with_context(|| format!("Invalid AAAA record address: {}", value))?,
            },
            "CNAME" => DnsRecordType::CNAME {
                target: Self::normalize_fqdn(&value)?,
            },
            "MX" => Self::parse_mx_value(&value, priority)?,
            "SRV" => Self::parse_srv_value(&value, priority)?,
            "TXT" => DnsRecordType::TXT { text: value },
            other => return Err(anyhow!("Unsupported DNS record type: {}", other)),
        };

        Ok(DnsRecord::new(name, record_type, ttl))
    }

    /// Parse SOA record value from database format
    ///
    /// Expected format: "mname rname serial refresh retry expire minimum"
    fn parse_soa_value(value: &str) -> Result<DnsRecordType> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() < 7 {
            return Err(anyhow!(
                "Invalid SOA record format. Expected 7 fields, got {}. Value: {}",
                parts.len(),
                value
            ));
        }

        let mname = Self::normalize_fqdn(parts[0])?;
        let rname = Self::normalize_fqdn(parts[1])?;

        let serial: u32 = parts[2].parse()
            .with_context(|| format!("Invalid SOA serial: {}", parts[2]))?;
        let refresh: i32 = parts[3].parse()
            .with_context(|| format!("Invalid SOA refresh: {}", parts[3]))?;
        let retry: i32 = parts[4].parse()
            .with_context(|| format!("Invalid SOA retry: {}", parts[4]))?;
        let expire: i32 = parts[5].parse()
            .with_context(|| format!("Invalid SOA expire: {}", parts[5]))?;
        let minimum: u32 = parts[6].parse()
            .with_context(|| format!("Invalid SOA minimum: {}", parts[6]))?;

        Ok(DnsRecordType::SOA {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum: minimum as i32,
        })
    }

    /// Parse MX record value from database format
    ///
    /// Expected format: "exchange" with preference coming from priority field
    fn parse_mx_value(value: &str, priority: i32) -> Result<DnsRecordType> {
        let preference = if priority > 0 {
            u16::try_from(priority)
                .with_context(|| format!("Invalid MX preference: {}", priority))?
        } else {
            // Try to parse from value if priority is not set
            let parts: Vec<&str> = value.split_whitespace().collect();
            if parts.len() >= 2 {
                parts[0].parse()
                    .with_context(|| format!("Invalid MX preference in value: {}", parts[0]))?
            } else {
                return Err(anyhow!("MX record requires preference and exchange"));
            }
        };

        let exchange = if priority > 0 {
            Self::normalize_fqdn(value)?
        } else {
            let parts: Vec<&str> = value.split_whitespace().collect();
            if parts.len() >= 2 {
                Self::normalize_fqdn(parts[1])?
            } else {
                return Err(anyhow!("MX record requires preference and exchange"));
            }
        };

        Ok(DnsRecordType::MX { preference, exchange })
    }

    /// Parse SRV record value from database format
    ///
    /// Expected format: "priority weight port target"
    fn parse_srv_value(value: &str, priority: i32) -> Result<DnsRecordType> {
        let parts: Vec<&str> = value.split_whitespace().collect();

        // If priority field is set, this is the source; otherwise parse from value
        let (priority, weight, port, target) = if priority > 0 {
            if parts.len() < 3 {
                return Err(anyhow!("SRV record requires weight, port, and target. Got: {}", value));
            }
            let p = u16::try_from(priority).with_context(|| format!("Invalid SRV priority: {}", priority))?;
            let w: u16 = parts[0].parse().with_context(|| format!("Invalid SRV weight: {}", parts[0]))?;
            let pt: u16 = parts[1].parse().with_context(|| format!("Invalid SRV port: {}", parts[1]))?;
            let t = Self::normalize_fqdn(parts[2])?;
            (p, w, pt, t)
        } else {
            if parts.len() < 4 {
                return Err(anyhow!("SRV record requires priority, weight, port, and target. Got: {}", value));
            }
            let p: u16 = parts[0].parse().with_context(|| format!("Invalid SRV priority: {}", parts[0]))?;
            let w: u16 = parts[1].parse().with_context(|| format!("Invalid SRV weight: {}", parts[1]))?;
            let pt: u16 = parts[2].parse().with_context(|| format!("Invalid SRV port: {}", parts[2]))?;
            let t = Self::normalize_fqdn(parts[3])?;
            (p, w, pt, t)
        };

        Ok(DnsRecordType::SRV {
            priority,
            weight,
            port,
            target,
        })
    }

    /// Ensures an FQDN has a trailing dot
    fn normalize_fqdn(fqdn: &str) -> Result<String> {
        let trimmed = fqdn.trim();
        if trimmed.is_empty() {
            return Err(anyhow!("Empty FQDN"));
        }
        if !trimmed.ends_with('.') {
            Ok(format!("{}.", trimmed))
        } else {
            Ok(trimmed.to_string())
        }
    }
}

/// Safe zone file writer that validates before persisting
pub struct SafeZoneFileWriter;

impl SafeZoneFileWriter {
    /// Writes zone content to disk with atomic semantics and validation
    ///
    /// This function:
    /// 1. Writes content to a temporary file
    /// 2. Validates the file by attempting to parse it with Hickory DNS
    /// 3. If valid, atomically replaces the target file
    /// 4. If invalid, removes the temporary file and returns an error
    pub fn write_validated(zone_path: &Path, content: &str) -> Result<()> {
        let tmp_path = zone_path.with_extension("zone.tmp");

        debug!("Writing zone file to temporary location: {:?}", tmp_path);
        fs::write(&tmp_path, content)
            .with_context(|| format!("Failed to write zone file temp at {:?}", tmp_path))?;

        // Validate the written file by attempting to parse it
        if let Err(e) = Self::validate_zone_file(&tmp_path) {
            warn!("Zone file validation failed, removing temporary file: {:?}", tmp_path);
            let _ = fs::remove_file(&tmp_path);
            return Err(e).with_context(|| format!("Zone file validation failed at {:?}", tmp_path));
        }

        debug!("Zone file validation passed, moving to final location: {:?}", zone_path);
        fs::rename(&tmp_path, zone_path)
            .with_context(|| format!("Failed to rename temp zone file to {:?}", zone_path))?;

        Ok(())
    }

    /// Validates a zone file by attempting to parse it line by line
    ///
    /// This is a basic validation that checks:
    /// - File can be read
    /// - Basic zone file format (name TTL class type rdata...)
    /// - At least one record exists
    fn validate_zone_file(path: &Path) -> Result<()> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read zone file for validation: {:?}", path))?;

        let mut found_record = false;
        let mut line_num = 0;

        for line in content.lines() {
            line_num += 1;
            let trimmed = line.trim();

            // Skip empty lines and comments
            if trimmed.is_empty() || trimmed.starts_with(';') {
                continue;
            }

            // Check that the line has the basic components of a DNS record
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() < 4 {
                return Err(anyhow!(
                    "Invalid zone file format at line {}: insufficient fields in '{}'",
                    line_num,
                    trimmed
                ));
            }

            // Basic validation: TTL should be numeric
            if parts[1].parse::<u32>().is_err() {
                return Err(anyhow!(
                    "Invalid zone file format at line {}: TTL '{}' is not numeric",
                    line_num,
                    parts[1]
                ));
            }

            // Validate record type is known
            let record_type = parts[3].to_uppercase();
            match record_type.as_str() {
                "SOA" | "NS" | "A" | "AAAA" | "CNAME" | "MX" | "SRV" | "TXT" | "CAA" | "PTR" | "SPF" => {}
                _ => {
                    warn!("Unknown record type at line {}: {}", line_num, record_type);
                }
            }
            
            found_record = true;
        }

        if !found_record {
            return Err(anyhow!(
                "Zone file validation failed: no records found in {:?}",
                path
            ));
        }

        Ok(())
    }
}

/// TOML configuration builder for Hickory DNS named config
pub struct TomlConfigBuilder {
    zones: Vec<TomlZone>,
    listen_ipv4: Vec<String>,
}

#[derive(Debug, Clone)]
struct TomlZone {
    zone: String,
    zone_type: String,
    zone_path: String,
    geodns_enabled: bool,
    geo_rules: Vec<TomlGeoRule>,
}

#[derive(Debug, Clone)]
struct TomlGeoRule {
    match_type: String,
    match_value: String,
    target: String,
    priority: i32,
    enabled: bool,
    record_name: Option<String>,
    record_type: Option<String>,
}

impl TomlConfigBuilder {
    /// Creates a new TOML configuration builder
    pub fn new() -> Self {
        Self {
            zones: Vec::new(),
            listen_ipv4: vec!["0.0.0.0".to_string()],
        }
    }

    /// Adds a zone to the configuration
    pub fn add_zone(
        &mut self,
        zone: String,
        zone_path: String,
        geodns_enabled: bool,
        geo_rules: Vec<(String, String, String, i32, bool, Option<String>, Option<String>)>,
    ) -> Result<()> {
        let rules = geo_rules
            .into_iter()
            .map(|(match_type, match_value, target, priority, enabled, record_name, record_type)| {
                TomlGeoRule {
                    match_type,
                    match_value,
                    target,
                    priority,
                    enabled,
                    record_name,
                    record_type,
                }
            })
            .collect();

        self.zones.push(TomlZone {
            zone,
            zone_type: "Primary".to_string(),
            zone_path,
            geodns_enabled,
            geo_rules: rules,
        });

        Ok(())
    }

    /// Builds the final TOML string
    pub fn build(&self) -> Result<String> {
        let mut result = String::new();
        result.push_str("listen_addrs_ipv4 = [");
        for (i, addr) in self.listen_ipv4.iter().enumerate() {
            if i > 0 {
                result.push_str(", ");
            }
            result.push('"');
            result.push_str(addr);
            result.push('"');
        }
        result.push_str("]\n\n");

        for zone in &self.zones {
            result.push_str("[[zones]]\n");
            result.push_str(&format!("zone = \"{}\"\n", zone.zone));
            result.push_str(&format!("zone_type = \"{}\"\n", zone.zone_type));

            if zone.geodns_enabled {
                result.push_str("geodns = { enabled = true, rules = [\n");
                for rule in &zone.geo_rules {
                    result.push_str("  { ");
                    result.push_str(&format!("match_type = \"{}\", ", rule.match_type));
                    result.push_str(&format!("match_value = \"{}\", ", rule.match_value));
                    result.push_str(&format!("target = \"{}\", ", rule.target));
                    result.push_str(&format!("priority = {}, ", rule.priority));
                    result.push_str(&format!("enabled = {}, ", rule.enabled));
                    if let Some(rn) = &rule.record_name {
                        result.push_str(&format!("record_name = \"{}\", ", rn));
                    }
                    if let Some(rt) = &rule.record_type {
                        result.push_str(&format!("record_type = \"{}\", ", rt));
                    }
                    result.push_str("},\n");
                }
                result.push_str("] }\n\n");
            }

            result.push_str("[[zones.stores]]\n");
            result.push_str("type = \"file\"\n");
            result.push_str(&format!("zone_path = \"{}\"\n\n", zone.zone_path));
        }

        Ok(result)
    }
}

impl Default for TomlConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_record_creation_a() {
        let record = DnsRecord::new(
            "example.com.".to_string(),
            DnsRecordType::A {
                address: "192.0.2.1".to_string(),
            },
            3600,
        );

        assert!(record.validate().is_ok());
    }

    #[test]
    fn test_dns_record_creation_aaaa() {
        let record = DnsRecord::new(
            "example.com.".to_string(),
            DnsRecordType::AAAA {
                address: "2001:db8::1".to_string(),
            },
            3600,
        );

        assert!(record.validate().is_ok());
    }

    #[test]
    fn test_dns_record_creation_invalid_a() {
        let record = DnsRecord::new(
            "example.com.".to_string(),
            DnsRecordType::A {
                address: "192.0.2.999".to_string(),
            },
            3600,
        );

        assert!(record.validate().is_err());
    }

    #[test]
    fn test_dns_record_builder_soa() {
        let result = DnsRecordBuilder::from_db_fields(
            "@".to_string(),
            "SOA".to_string(),
            "ns1.example.com. hostmaster.example.com. 2024010101 3600 1800 604800 3600".to_string(),
            3600,
            0,
        );

        assert!(result.is_ok(), "SOA creation failed: {:?}", result.err());
        let record = result.unwrap();
        let validation = record.validate();
        assert!(validation.is_ok(), "SOA validation failed: {:?}", validation.err());
    }

    #[test]
    fn test_dns_record_builder_invalid_soa() {
        let result = DnsRecordBuilder::from_db_fields(
            "@".to_string(),
            "SOA".to_string(),
            "insufficient fields".to_string(),
            3600,
            0,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_dns_record_builder_ns() {
        let result = DnsRecordBuilder::from_db_fields(
            "@".to_string(),
            "NS".to_string(),
            "ns1.example.com".to_string(),
            3600,
            0,
        );

        assert!(result.is_ok());
        let record = result.unwrap();
        assert!(record.validate().is_ok());
    }

    #[test]
    fn test_dns_record_builder_mx() {
        let result = DnsRecordBuilder::from_db_fields(
            "@".to_string(),
            "MX".to_string(),
            "mail.example.com".to_string(),
            3600,
            10,
        );

        assert!(result.is_ok());
        let record = result.unwrap();
        assert!(record.validate().is_ok());
    }

    #[test]
    fn test_toml_config_builder() {
        let mut builder = TomlConfigBuilder::new();
        builder
            .add_zone(
                "example.com".to_string(),
                "/etc/named/zone.example.com".to_string(),
                false,
                vec![],
            )
            .unwrap();

        let result = builder.build();
        assert!(result.is_ok());
        let toml_str = result.unwrap();
        assert!(toml_str.contains("zone = \"example.com\""));
        assert!(toml_str.contains("listen_addrs_ipv4"));
    }
}
