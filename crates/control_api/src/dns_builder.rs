//! Type-safe DNS record builder module
//!
//! This module provides strongly-typed APIs for building DNS records and zones using
//! Hickory DNS types, eliminating all string-based DNS generation. All records are
//! validated before persistence using Hickory DNS validation APIs.

use anyhow::{anyhow, Context, Result};
use hickory_proto::rr::{domain::Name, Record};
use std::fs;
use std::path::Path;
use log::{debug, warn};

use crate::dns_validator::{
    validate_record,
    validate_zone_file,
    validate_record_name_input,
    validate_record_type,
    validate_record_value,
    validate_ttl,
};

/// Represents a complete DNS record with all metadata.
#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub name: String,
    pub record_type: String,
    pub value: String,
    pub ttl: u32,
}

impl DnsRecord {
    /// Creates a new DNS record with the given parameters.
    pub fn new(name: String, record_type: String, value: String, ttl: u32) -> Self {
        Self {
            name,
            record_type,
            value,
            ttl,
        }
    }

    /// Converts this DnsRecord into a Hickory Record.
    /// This delegates ALL record validation to Hickory DNS via validate_record().
    pub fn to_hickory_record(&self) -> Result<Record> {
        validate_record(&self.name, &self.record_type, &self.value, self.ttl, None)
            .map_err(|err| anyhow!(err.to_string()))
    }

    /// Return the record in zone file text format.
    /// Validates by converting to Hickory Record first.
    pub fn to_zone_string(&self) -> Result<String> {
        Ok(self.to_hickory_record()?.to_string())
    }

    /// Validates that this record can be converted to a Hickory Record.
    /// Uses Hickory DNS APIs for all validation (zero custom logic).
    pub fn validate(&self) -> Result<()> {
        // Validate name through Hickory
        validate_record_name_input(&self.name)
            .map_err(|err| anyhow!(err.to_string()))?;

        // Validate record type through Hickory
        validate_record_type(&self.record_type)
            .map_err(|err| anyhow!(err.to_string()))?;

        // Validate TTL (simple numeric check)
        validate_ttl(self.ttl)
            .map_err(|err| anyhow!(err.to_string()))?;

        // Validate record value through Hickory - KEY VALIDATION
        // This delegates to RData::try_from_str() which does all record-type-specific validation
        validate_record_value(&self.record_type, &self.value)
            .map_err(|err| anyhow!(err.to_string()))?;

        // Final validation: can we construct a Hickory Record?
        // This confirms all parts work together
        if self.name == "@" {
            Ok(())
        } else {
            self.to_hickory_record().map(|_| ())
        }
    }
}

/// Builder for creating DNS records from database-style data.
pub struct DnsRecordBuilder;

impl DnsRecordBuilder {
    /// Creates a DnsRecord from database fields with Hickory validation.
    /// All record-type-specific validation delegates to Hickory DNS.
    pub fn from_db_fields(
        name: String,
        rtype: String,
        value: String,
        ttl: i32,
        priority: i32,
    ) -> Result<DnsRecord> {
        let ttl = u32::try_from(ttl).with_context(|| format!("Invalid TTL value: {}", ttl))?;

        let record_type = rtype.trim().to_ascii_uppercase();
        let normalized_value = Self::normalize_value(&record_type, &value, priority);

        let record = DnsRecord::new(name, record_type, normalized_value, ttl);
        // Validate through Hickory before returning
        record.validate()?;
        Ok(record)
    }

    /// Normalizes record value for certain types (e.g., adding priority to MX/SRV).
    /// This handles database schema differences, not DNS validation.
    fn normalize_value(record_type: &str, value: &str, priority: i32) -> String {
        let trimmed = value.trim();
        match record_type {
            "MX" => {
                let mut tokens = trimmed.split_whitespace();
                if priority > 0 && tokens.next().map_or(true, |first| first.parse::<u16>().is_err()) {
                    format!("{} {}", priority, trimmed)
                } else {
                    trimmed.to_string()
                }
            }
            "SRV" => {
                let tokens: Vec<&str> = trimmed.split_whitespace().collect();
                if priority > 0 {
                    match tokens.len() {
                        1 => format!("{} 0 0 {}", priority, trimmed),
                        3 => format!("{} {}", priority, trimmed),
                        4 => trimmed.to_string(),
                        _ => trimmed.to_string(),
                    }
                } else if tokens.len() == 3 {
                    format!("0 {}", trimmed)
                } else {
                    trimmed.to_string()
                }
            }
            _ => trimmed.to_string(),
        }
    }
}

/// Safe zone file writer that validates before persisting.
pub struct SafeZoneFileWriter;

impl SafeZoneFileWriter {
    /// Writes zone content to disk with atomic semantics and Hickory validation.
    /// Zone file is validated by Hickory's parser before committing.
    pub fn write_validated(
        zone_path: &Path,
        content: &str,
        origin: Option<&hickory_proto::rr::domain::Name>,
    ) -> Result<()> {
        let tmp_path = zone_path.with_extension("zone.tmp");

        debug!("Writing zone file to temporary location: {:?}", tmp_path);
        fs::write(&tmp_path, content)
            .with_context(|| format!("Failed to write zone file temp at {:?}", tmp_path))?;

        // Validate zone file using Hickory's parser - delegates to Hickory
        if let Err(e) = validate_zone_file(&tmp_path, content, origin) {
            warn!("Zone file validation failed, removing temporary file: {:?}", tmp_path);
            let _ = fs::remove_file(&tmp_path);
            return Err(e).with_context(|| format!("Zone file validation failed at {:?}", tmp_path));
        }

        debug!("Zone file validation passed, moving to final location: {:?}", zone_path);
        fs::rename(&tmp_path, zone_path)
            .with_context(|| format!("Failed to rename temp zone file to {:?}", zone_path))?;

        Ok(())
    }
}

/// TOML configuration builder for Hickory DNS named config.
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
    /// Creates a new TOML configuration builder.
    pub fn new() -> Self {
        Self {
            zones: Vec::new(),
            listen_ipv4: vec!["0.0.0.0".to_string()],
        }
    }

    /// Adds a zone to the configuration.
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

    /// Builds the final TOML string.
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
            "A".to_string(),
            "192.0.2.1".to_string(),
            3600,
        );

        assert!(record.validate().is_ok());
    }

    #[test]
    fn test_dns_record_creation_aaaa() {
        let record = DnsRecord::new(
            "example.com.".to_string(),
            "AAAA".to_string(),
            "2001:db8::1".to_string(),
            3600,
        );

        assert!(record.validate().is_ok());
    }

    #[test]
    fn test_dns_record_creation_invalid_a() {
        let record = DnsRecord::new(
            "example.com.".to_string(),
            "A".to_string(),
            "192.0.2.999".to_string(),
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
        assert!(record.validate().is_ok());
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
            "ns1.example.com.".to_string(),
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
            "mail.example.com.".to_string(),
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

    // Comprehensive validation tests verifying Hickory delegation

    #[test]
    fn test_aaaa_record_validation_through_hickory() {
        let record = DnsRecord::new(
            "ipv6.example.com.".to_string(),
            "AAAA".to_string(),
            "2001:db8::1".to_string(),
            3600,
        );
        assert!(record.validate().is_ok());
    }

    #[test]
    fn test_invalid_aaaa_record_rejected_by_hickory() {
        let record = DnsRecord::new(
            "ipv6.example.com.".to_string(),
            "AAAA".to_string(),
            "invalid-ipv6".to_string(),
            3600,
        );
        assert!(record.validate().is_err(), "Hickory should reject invalid IPv6");
    }

    #[test]
    fn test_txt_record_validation_through_hickory() {
        let record = DnsRecord::new(
            "txt.example.com.".to_string(),
            "TXT".to_string(),
            "\"v=spf1 mx -all\"".to_string(),
            3600,
        );
        assert!(record.validate().is_ok());
    }

    #[test]
    fn test_srv_record_validation_through_hickory() {
        let record = DnsRecord::new(
            "_sip._tcp.example.com.".to_string(),
            "SRV".to_string(),
            "10 20 5060 sipserver.example.com.".to_string(),
            3600,
        );
        assert!(record.validate().is_ok());
    }

    #[test]
    fn test_caa_record_validation_through_hickory() {
        let record = DnsRecord::new(
            "example.com.".to_string(),
            "CAA".to_string(),
            "0 issue \"ca.example.com\"".to_string(),
            3600,
        );
        assert!(record.validate().is_ok());
    }

    #[test]
    fn test_tlsa_record_validation_through_hickory() {
        let record = DnsRecord::new(
            "_443._tcp.example.com.".to_string(),
            "TLSA".to_string(),
            "3 1 1 d2abde240d7cd3ee6b4b28c54df034b97983a1d16e8a410e4561cb106618e971".to_string(),
            3600,
        );
        assert!(record.validate().is_ok());
    }

    #[test]
    fn test_invalid_record_type_rejected() {
        let record = DnsRecord::new(
            "example.com.".to_string(),
            "INVALID_TYPE".to_string(),
            "1.2.3.4".to_string(),
            3600,
        );
        assert!(record.validate().is_err(), "Hickory should reject invalid record type");
    }

    #[test]
    fn test_zero_ttl_rejected() {
        let record = DnsRecord::new(
            "example.com.".to_string(),
            "A".to_string(),
            "1.2.3.4".to_string(),
            0,
        );
        assert!(record.validate().is_err(), "TTL of 0 should be rejected");
    }

    #[test]
    fn test_invalid_domain_name_rejected() {
        let record = DnsRecord::new(
            "invalid..domain".to_string(),
            "A".to_string(),
            "1.2.3.4".to_string(),
            3600,
        );
        assert!(record.validate().is_err(), "Invalid domain names should be rejected by Hickory");
    }

    #[test]
    fn test_builder_validates_through_hickory() {
        let result = DnsRecordBuilder::from_db_fields(
            "test.example.com.".to_string(),
            "AAAA".to_string(),
            "invalid-ip".to_string(),
            3600,
            0,
        );
        assert!(result.is_err(), "Builder should validate through Hickory and reject invalid IPv6");
    }

    #[test]
    fn test_mx_record_with_priority_validation() {
        let result = DnsRecordBuilder::from_db_fields(
            "@".to_string(),
            "MX".to_string(),
            "mail.example.com.".to_string(),
            3600,
            25,
        );
        assert!(result.is_ok(), "MX record with priority should validate through Hickory");
    }

    #[test]
    fn test_ptr_record_validation_through_hickory() {
        let record = DnsRecord::new(
            "1.2.3.4.in-addr.arpa.".to_string(),
            "PTR".to_string(),
            "mail.example.com.".to_string(),
            3600,
        );
        assert!(record.validate().is_ok());
    }

    #[test]
    fn test_cname_record_validation_through_hickory() {
        let record = DnsRecord::new(
            "alias.example.com.".to_string(),
            "CNAME".to_string(),
            "canonical.example.com.".to_string(),
            3600,
        );
        assert!(record.validate().is_ok());
    }

    #[test]
    fn test_soa_record_validation_through_hickory() {
        let record = DnsRecord::new(
            "example.com.".to_string(),
            "SOA".to_string(),
            "ns1.example.com. hostmaster.example.com. 2024010101 3600 1800 604800 3600".to_string(),
            3600,
        );
        assert!(record.validate().is_ok());
    }

    #[test]
    fn test_invalid_soa_record_rejected_by_hickory() {
        let record = DnsRecord::new(
            "example.com.".to_string(),
            "SOA".to_string(),
            "incomplete soa record".to_string(),
            3600,
        );
        assert!(record.validate().is_err(), "Hickory should reject invalid SOA format");
    }
}
