use std::{fmt, path::Path};
use std::str::FromStr;

use hickory_proto::rr::{domain::Name, RData, Record, RecordType};
use hickory_proto::serialize::txt::{Parser, RDataParser};

/// Validation failure returned to the control API.
#[derive(Debug)]
pub struct ValidationError {
    pub field: String,
    pub message: String,
}

impl ValidationError {
    pub fn new(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.field, self.message)
    }
}

impl std::error::Error for ValidationError {}

fn normalize_to_fqdn(value: &str) -> String {
    let trimmed = value.trim();

    if trimmed.ends_with('.') {
        trimmed.to_string()
    } else {
        format!("{}.", trimmed)
    }
}

/// Validate a zone domain by parsing it as a fully-qualified domain name.
pub fn validate_zone_domain(domain: &str) -> Result<(), ValidationError> {
    let normalized = normalize_to_fqdn(domain);
    Name::from_utf8(&normalized)
        .map(|_| ())
        .map_err(|err| ValidationError::new("domain", err.to_string()))
}

/// Validate a record name with an optional zone origin.
///
/// Record names may be absolute or relative. The special value `@` refers to
/// the zone origin and requires an origin to be provided.
pub fn validate_record_name(
    name: &str,
    origin: Option<&Name>,
) -> Result<Name, ValidationError> {
    let trimmed = name.trim();

    if trimmed.is_empty() {
        return Err(ValidationError::new("name", "Record name cannot be empty"));
    }

    if trimmed == "@" {
        return origin
            .cloned()
            .ok_or_else(|| ValidationError::new("name", "Zone origin is required for '@' record name"));
    }

    let fqdn = if trimmed.ends_with('.') {
        trimmed.to_string()
    } else if let Some(origin) = origin {
        format!("{}.{}", trimmed.trim_end_matches('.'), origin)
    } else {
        normalize_to_fqdn(trimmed)
    };

    Name::from_utf8(&fqdn).map_err(|err| ValidationError::new("name", err.to_string()))
}

/// Validate a DNS record type string using Hickory's RecordType parser.
pub fn validate_record_type(record_type: &str) -> Result<RecordType, ValidationError> {
    let trimmed = record_type.trim();
    let parsed = RecordType::from_str(&trimmed.to_ascii_uppercase())
        .map_err(|err| ValidationError::new("record_type", err.to_string()))?;

    Ok(parsed)
}

/// Validates a record name string without requiring a zone origin.
pub fn validate_record_name_input(name: &str) -> Result<(), ValidationError> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(ValidationError::new("name", "Record name cannot be empty"));
    }

    if trimmed == "@" {
        return Ok(());
    }

    let fqdn = if trimmed.ends_with('.') {
        trimmed.to_string()
    } else {
        normalize_to_fqdn(trimmed)
    };

    Name::from_utf8(&fqdn)
        .map(|_| ())
        .map_err(|err| ValidationError::new("name", err.to_string()))
}

/// Validate a DNS record type string using Hickory's RecordType parser.
pub fn validate_record_value(
    record_type: &str,
    value: &str,
) -> Result<RData, ValidationError> {
    let record_type = validate_record_type(record_type)?;
    RData::try_from_str(record_type, value)
        .map_err(|err| ValidationError::new("value", err.to_string()))
}

/// Validate that TTL is a non-zero value.
pub fn validate_ttl(ttl: u32) -> Result<(), ValidationError> {
    if ttl == 0 {
        Err(ValidationError::new("ttl", "TTL must be greater than zero"))
    } else {
        Ok(())
    }
}

/// Validate MX priority is within the allowed 16-bit range.
pub fn validate_mx_priority(priority: i32) -> Result<(), ValidationError> {
    if priority < 0 || priority > u16::MAX as i32 {
        Err(ValidationError::new("priority", "MX priority must be between 0 and 65535"))
    } else {
        Ok(())
    }
}

/// Validate NS record value against a configured set of allowed nameservers.
pub fn validate_ns_value(value: &str, allowed_nameservers: &[String]) -> Result<(), ValidationError> {
    if allowed_nameservers.is_empty() {
        return Ok(());
    }

    let normalized_value = normalize_to_fqdn(value.trim());
    let allowed_normalized: Vec<String> = allowed_nameservers
        .iter()
        .map(|ns| normalize_to_fqdn(ns.trim()))
        .collect();

    if allowed_normalized.contains(&normalized_value) {
        Ok(())
    } else {
        Err(ValidationError::new(
            "value",
            format!("NS target '{}' is not an allowed nameserver", value),
        ))
    }
}

/// Return the configured global nameservers from environment or fallback defaults.
pub fn get_global_nameservers() -> Vec<String> {
    let env = std::env::var("PUBLIC_NAMESERVERS").unwrap_or_else(|_| {
        "ns1.my-dns.com.,ns2.my-dns.com.".to_string()
    });

    env.split(',')
        .filter_map(|s| {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(normalize_to_fqdn(trimmed))
            }
        })
        .collect()
}

/// Validate a record and return the constructed Hickory Record.
pub fn validate_record(
    name: &str,
    record_type: &str,
    value: &str,
    ttl: u32,
    origin: Option<&Name>,
) -> Result<Record, ValidationError> {
    let name = validate_record_name(name, origin)?;
    let rdata = validate_record_value(record_type, value)?;
    Ok(Record::from_rdata(name, ttl, rdata))
}

/// Validate raw zone text using Hickory's zone file parser.
pub fn validate_zone_text(
    content: &str,
    origin: Option<&Name>,
) -> Result<(), ValidationError> {
    let origin = origin.cloned();
    let (_origin, records) = Parser::new(content.to_string(), None, origin)
        .parse()
        .map_err(|err| ValidationError::new("zone_file", err.to_string()))?;

    if records.is_empty() {
        return Err(ValidationError::new(
            "zone_file",
            "Zone file contains no records",
        ));
    }

    Ok(())
}

/// Validate written zone file contents by parsing them with Hickory's zone parser.
pub fn validate_zone_file(
    path: &Path,
    content: &str,
    origin: Option<&Name>,
) -> Result<(), ValidationError> {
    let origin = origin.cloned();
    let (_origin, records) = Parser::new(content.to_string(), Some(path.to_owned()), origin)
        .parse()
        .map_err(|err| ValidationError::new("zone_file", err.to_string()))?;

    if records.is_empty() {
        return Err(ValidationError::new(
            "zone_file",
            "Zone file contains no records",
        ));
    }

    Ok(())
}

/// Zone-level consistency validator for CNAME conflicts.
/// CNAME records cannot coexist with other records at the same name (RFC 1035).
pub async fn validate_cname_conflicts(
    db: &tokio_postgres::Client,
    zone_id: &str,
    name: &str,
    record_type: &str,
) -> Result<(), ValidationError> {
    let rtype_upper = record_type.to_uppercase();
    let normalized_name = if name == "@" || name.is_empty() {
        "@".to_string()
    } else {
        name.trim_end_matches('.').to_string()
    };

    if rtype_upper == "CNAME" {
        // Adding CNAME: check no other records exist at this name
        let other_exists = db
            .query_opt(
                "SELECT id FROM records WHERE CAST(zone_id AS varchar) = $1 AND name = $2 AND type != 'CNAME'",
                &[&zone_id, &normalized_name],
            )
            .await
            .map_err(|e| ValidationError::new("database", e.to_string()))?;

        if other_exists.is_some() {
            return Err(ValidationError::new(
                "record",
                "Cannot add CNAME: other record types already exist at this name. CNAME cannot coexist with other records.",
            ));
        }
    } else {
        // Adding non-CNAME: check CNAME doesn't exist at this name
        let cname_exists = db
            .query_opt(
                "SELECT id FROM records WHERE CAST(zone_id AS varchar) = $1 AND name = $2 AND type = 'CNAME'",
                &[&zone_id, &normalized_name],
            )
            .await
            .map_err(|e| ValidationError::new("database", e.to_string()))?;

        if cname_exists.is_some() {
            return Err(ValidationError::new(
                "record",
                "CNAME record already exists at this name. Cannot add other record types when CNAME exists.",
            ));
        }
    }

    Ok(())
}

/// Zone-level consistency validator: zone must have an SOA record.
pub async fn validate_zone_has_soa(
    db: &tokio_postgres::Client,
    zone_id: &str,
) -> Result<(), ValidationError> {
    let soa_exists = db
        .query_opt(
            "SELECT id FROM records WHERE CAST(zone_id AS varchar) = $1 AND type = 'SOA'",
            &[&zone_id],
        )
        .await
        .map_err(|e| ValidationError::new("database", e.to_string()))?;

    if soa_exists.is_none() {
        return Err(ValidationError::new(
            "zone",
            "Zone must have an SOA (Start of Authority) record",
        ));
    }

    Ok(())
}

/// Zone-level consistency validator: zone must have NS records.
pub async fn validate_zone_has_ns(
    db: &tokio_postgres::Client,
    zone_id: &str,
) -> Result<(), ValidationError> {
    let ns_exists = db
        .query_opt(
            "SELECT id FROM records WHERE CAST(zone_id AS varchar) = $1 AND type = 'NS'",
            &[&zone_id],
        )
        .await
        .map_err(|e| ValidationError::new("database", e.to_string()))?;

    if ns_exists.is_none() {
        return Err(ValidationError::new(
            "zone",
            "Zone must have at least one NS (Name Server) record",
        ));
    }

    Ok(())
}

/// Zone-level consistency validator: SOA records must be unique at zone apex.
pub async fn validate_no_duplicate_soa(
    db: &tokio_postgres::Client,
    zone_id: &str,
) -> Result<(), ValidationError> {
    let soa_count: i64 = db
        .query_one(
            "SELECT COUNT(*) as count FROM records WHERE CAST(zone_id AS varchar) = $1 AND type = 'SOA'",
            &[&zone_id],
        )
        .await
        .map_err(|e| ValidationError::new("database", e.to_string()))?
        .try_get(0)
        .unwrap_or(0);

    if soa_count > 1 {
        return Err(ValidationError::new(
            "zone",
            "Zone can have only one SOA record",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_zone_domain_valid() {
        assert!(validate_zone_domain("example.com").is_ok());
        assert!(validate_zone_domain("example.com.").is_ok());
        assert!(validate_zone_domain("sub.domain.example.com.").is_ok());
    }

    #[test]
    fn test_validate_zone_domain_invalid() {
        assert!(validate_zone_domain("invalid..domain.").is_err());
        assert!(validate_zone_domain("").is_err());
    }

    #[test]
    fn test_validate_record_name_at_symbol() {
        let origin = Name::from_utf8("example.com.").unwrap();
        let result = validate_record_name("@", Some(&origin));
        assert!(result.is_ok());
        assert_eq!(result.unwrap().to_utf8(), "example.com.");
    }

    #[test]
    fn test_validate_record_name_relative() {
        let origin = Name::from_utf8("example.com.").unwrap();
        let result = validate_record_name("www", Some(&origin));
        assert!(result.is_ok());
        assert_eq!(result.unwrap().to_utf8(), "www.example.com.");
    }

    #[test]
    fn test_validate_record_name_absolute() {
        let result = validate_record_name("www.example.com.", None);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().to_utf8(), "www.example.com.");
    }

    #[test]
    fn test_validate_record_type_all_common_types() {
        let types = vec!["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT", "SRV", "CAA", "PTR"];
        for rtype in types {
            assert!(validate_record_type(rtype).is_ok(), "Type {} should validate", rtype);
        }
    }

    #[test]
    fn test_validate_record_type_invalid() {
        assert!(validate_record_type("INVALID_TYPE_XYZ").is_err());
    }

    #[test]
    fn test_validate_record_value_a_record_through_hickory() {
        // Valid A record - delegated to Hickory via RData::try_from_str()
        assert!(validate_record_value("A", "192.0.2.1").is_ok());
    }

    #[test]
    fn test_validate_record_value_invalid_a_through_hickory() {
        // Invalid A record - Hickory rejects it
        assert!(validate_record_value("A", "invalid-ip").is_err());
        assert!(validate_record_value("A", "256.256.256.256").is_err());
    }

    #[test]
    fn test_validate_record_value_aaaa_through_hickory() {
        assert!(validate_record_value("AAAA", "2001:db8::1").is_ok());
    }

    #[test]
    fn test_validate_record_value_invalid_aaaa_through_hickory() {
        assert!(validate_record_value("AAAA", "invalid-ipv6").is_err());
    }

    #[test]
    fn test_validate_record_value_mx_through_hickory() {
        assert!(validate_record_value("MX", "10 mail.example.com.").is_ok());
    }

    #[test]
    fn test_validate_record_value_invalid_mx_through_hickory() {
        assert!(validate_record_value("MX", "invalid mx record").is_err());
    }

    #[test]
    fn test_validate_record_value_txt_through_hickory() {
        assert!(validate_record_value("TXT", "\"v=spf1 mx -all\"").is_ok());
    }

    #[test]
    fn test_validate_record_value_soa_through_hickory() {
        let soa = "ns1.example.com. hostmaster.example.com. 2024010101 3600 1800 604800 3600";
        assert!(validate_record_value("SOA", soa).is_ok());
    }

    #[test]
    fn test_validate_record_value_invalid_soa_through_hickory() {
        assert!(validate_record_value("SOA", "incomplete").is_err());
    }

    #[test]
    fn test_validate_record_value_caa_through_hickory() {
        assert!(validate_record_value("CAA", "0 issue \"ca.example.com\"").is_ok());
    }

    #[test]
    fn test_validate_record_value_tlsa_through_hickory() {
        let tlsa = "3 1 1 d2abde240d7cd3ee6b4b28c54df034b97983a1d16e8a410e4561cb106618e971";
        assert!(validate_record_value("TLSA", tlsa).is_ok());
    }

    #[test]
    fn test_validate_ttl_valid() {
        assert!(validate_ttl(1).is_ok());
        assert!(validate_ttl(3600).is_ok());
        assert!(validate_ttl(u32::MAX).is_ok());
    }

    #[test]
    fn test_validate_ttl_zero_rejected() {
        assert!(validate_ttl(0).is_err());
    }

    #[test]
    fn test_validate_mx_priority_valid() {
        assert!(validate_mx_priority(0).is_ok());
        assert!(validate_mx_priority(10).is_ok());
        assert!(validate_mx_priority(65535).is_ok());
    }

    #[test]
    fn test_validate_mx_priority_invalid() {
        assert!(validate_mx_priority(-1).is_err());
        assert!(validate_mx_priority(65536).is_err());
    }

    #[test]
    fn test_validate_record_complete_a_record() {
        let record = validate_record(
            "example.com.",
            "A",
            "192.0.2.1",
            3600,
            None,
        );
        assert!(record.is_ok());
    }

    #[test]
    fn test_validate_zone_text_valid() {
        let zone = "example.com. 3600 IN SOA ns1.example.com. hostmaster.example.com. 1 3600 1800 604800 3600
example.com. 3600 IN NS ns1.example.com.
www.example.com. 3600 IN A 192.0.2.1";
        assert!(validate_zone_text(zone, None).is_ok());
    }

    #[test]
    fn test_validate_zone_text_empty_rejected() {
        assert!(validate_zone_text("", None).is_err());
    }

    #[test]
    fn test_validation_error_display() {
        let err = ValidationError::new("test_field", "test message");
        assert_eq!(err.to_string(), "test_field: test message");
    }

    #[test]
    fn test_normalize_to_fqdn() {
        assert_eq!(normalize_to_fqdn("example"), "example.");
        assert_eq!(normalize_to_fqdn("example."), "example.");
        assert_eq!(normalize_to_fqdn("  example  "), "example.");
    }

    #[test]
    fn test_ns_value_normalization() {
        let allowed = vec!["ns1.example.com.".to_string(), "ns2.example.com.".to_string()];
        assert!(validate_ns_value("ns1.example.com.", &allowed).is_ok());
        assert!(validate_ns_value("ns1.example.com", &allowed).is_ok());
        assert!(validate_ns_value("ns3.example.com.", &allowed).is_err());
    }

    #[test]
    fn test_global_nameservers_from_env() {
        let ns = get_global_nameservers();
        assert!(!ns.is_empty());
        assert!(ns[0].ends_with('.'));
    }
}
