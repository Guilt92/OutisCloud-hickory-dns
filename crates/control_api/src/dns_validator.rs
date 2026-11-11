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

/// Normalise and strictly validate a zone apex.
///
/// Returns the canonical form stored in the database and used for zone file
/// names: lower-case, no trailing dot, LDH labels only (RFC 1035 / 1123), at
/// least two labels (the root and single-label TLD zones are never valid
/// tenant zones) and at most 253 characters. Anything else (slashes, quotes,
/// whitespace, TOML metacharacters, ...) is rejected so a domain can never
/// reach a file name or `named.toml` unescaped.
pub fn normalize_zone_domain(domain: &str) -> Result<String, ValidationError> {
    let d = domain.trim();
    let d = d.strip_suffix('.').unwrap_or(d).to_ascii_lowercase();
    if d.is_empty() {
        return Err(ValidationError::new("domain", "Domain cannot be empty"));
    }
    if d.len() > 253 {
        return Err(ValidationError::new("domain", "Domain exceeds 253 characters"));
    }
    let labels: Vec<&str> = d.split('.').collect();
    if labels.len() < 2 {
        return Err(ValidationError::new(
            "domain",
            "Domain must contain at least two labels (for example example.com)",
        ));
    }
    for label in labels {
        if label.is_empty() || label.len() > 63 {
            return Err(ValidationError::new("domain", "Each label must be 1-63 characters"));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(ValidationError::new("domain", "Labels must not start or end with '-'"));
        }
        if !label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
            return Err(ValidationError::new(
                "domain",
                "Labels may only contain letters, digits and '-' (use punycode for IDN)",
            ));
        }
    }
    // Final structural check through Hickory.
    Name::from_utf8(format!("{}.", d)).map_err(|err| ValidationError::new("domain", err.to_string()))?;
    Ok(d)
}

/// Validate a zone domain (see [`normalize_zone_domain`]).
pub fn validate_zone_domain(domain: &str) -> Result<(), ValidationError> {
    normalize_zone_domain(domain).map(|_| ())
}

/// Check that a record owner name is allowed inside zone `domain`.
///
/// Relative names and `@` are always inside the zone. Absolute names (trailing
/// dot) must be the apex or below it, otherwise they would be emitted into the
/// zone file for a name the zone is not authoritative for. Label characters are
/// restricted to those that are safe in a zone file (`a-z 0-9 - _ *`).
pub fn validate_record_in_zone(name: &str, domain: &str) -> Result<(), ValidationError> {
    let n = name.trim();
    if n == "@" {
        return Ok(());
    }
    let parsed = Name::from_utf8(if n.ends_with('.') { n.to_string() } else { format!("{}.", n) })
        .map_err(|err| ValidationError::new("name", err.to_string()))?;
    let ascii = parsed.to_ascii().to_ascii_lowercase();
    let ascii_base = ascii.trim_end_matches('.');
    if ascii_base.is_empty() {
        return Err(ValidationError::new("name", "Record name cannot be the root"));
    }
    for label in ascii_base.split('.') {
        if label.is_empty()
            || label.len() > 63
            || !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'*')
        {
            return Err(ValidationError::new(
                "name",
                "Record name labels may only contain letters, digits, '-', '_' and '*'",
            ));
        }
    }
    if n.ends_with('.') {
        let dom = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if !(ascii_base == dom || ascii_base.ends_with(&format!(".{}", dom))) {
            return Err(ValidationError::new(
                "name",
                format!("Record name '{}' is outside zone '{}'", name, dom),
            ));
        }
    }
    Ok(())
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
        let origin_str = origin.to_string();
        let origin_base = origin_str.trim_end_matches('.');
        // If the name already contains the zone domain (e.g. "ns1.example.com"
        // for origin "example.com.") it only needs to be made absolute.
        if trimmed == origin_base || trimmed.ends_with(&format!(".{}", origin_base)) {
            normalize_to_fqdn(trimmed)
        } else {
            format!("{}.{}", trimmed.trim_end_matches('.'), origin)
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_is_normalised() {
        assert_eq!(normalize_zone_domain("Example.COM.").unwrap(), "example.com");
        assert_eq!(normalize_zone_domain("  a-b.example.co.uk ").unwrap(), "a-b.example.co.uk");
        assert_eq!(normalize_zone_domain("xn--bcher-kva.example").unwrap(), "xn--bcher-kva.example");
    }

    #[test]
    fn dangerous_or_degenerate_domains_are_rejected() {
        for bad in [
            "", ".", "..", "com", "com.", "a..b", "-a.com", "a-.com", "a b.com", "a/b.com", "a\\b.com",
            "a\"b.com", "a'b.com", "a\nb.com", "a_b.com", "ü.com", "../x.com", "a.com/../b", "%41.com",
        ] {
            assert!(normalize_zone_domain(bad).is_err(), "{bad:?} must be rejected");
        }
        assert!(normalize_zone_domain(&format!("{}.com", "a".repeat(64))).is_err());
        assert!(normalize_zone_domain(&format!("{}.com", vec!["a".repeat(63); 4].join("."))).is_err());
    }

    #[test]
    fn record_names_must_stay_inside_the_zone() {
        for ok in ["@", "www", "a.b", "_sip._tcp", "*", "*.dev", "www.example.com.", "example.com.", "WWW"] {
            assert!(validate_record_in_zone(ok, "example.com").is_ok(), "{ok}");
        }
        for bad in ["www.other.org.", "example.com.evil.net.", "notexample.com.", ".", "a b", "a\"b", "a/b"] {
            assert!(validate_record_in_zone(bad, "example.com").is_err(), "{bad}");
        }
    }
}
