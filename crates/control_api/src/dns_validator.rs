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
