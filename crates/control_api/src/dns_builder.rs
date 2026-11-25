//! Type-safe DNS record builder module
//!
//! This module provides strongly-typed APIs for building DNS records and zones using
//! Hickory DNS types, eliminating all string-based DNS generation. All records are
//! validated before persistence using Hickory DNS validation APIs.

use anyhow::{Context, Result, anyhow};
use hickory_proto::rr::{Name, RData, Record};
use log::{debug, warn};
use std::fs;
use std::path::Path;

use crate::dns_validator::{
    validate_record, validate_record_name_input, validate_record_type, validate_record_value,
    validate_ttl, validate_zone_file,
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

    /// Return the record in zone file text format, qualifying any relative
    /// names embedded in the RDATA (e.g. SOA mname/rname) with the zone origin.
    ///
    /// Record values coming from the database may contain domain names without a
    /// trailing dot (for example `ns1.uid0.ir` instead of `ns1.uid0.ir.`). When
    /// such a relative name is written to a zone file the Hickory zone parser
    /// appends the origin again, producing doubled names such as
    /// `ns1.uid0.ir.uid0.ir.`. This method rewrites relative RDATA names so the
    /// generated zone file contains fully-qualified names instead.
    pub fn to_zone_string_with_origin(&self, origin: &Name) -> Result<String> {
        self.to_zone_string_with_origin_and_serial(origin, None)
    }

    /// Serial number carried by this record if it is an SOA.
    pub fn soa_serial(&self) -> Option<u32> {
        match self.to_hickory_record().ok()?.data() {
            RData::SOA(soa) => Some(soa.serial()),
            _ => None,
        }
    }

    /// Like [`to_zone_string_with_origin`](Self::to_zone_string_with_origin) but
    /// overrides the serial when this record is an SOA.
    pub fn to_zone_string_with_origin_and_serial(
        &self,
        origin: &Name,
        serial: Option<u32>,
    ) -> Result<String> {
        let mut record = self.to_hickory_record()?;
        let mut data = absolutize_rdata(record.data().clone(), origin);
        if let (Some(serial), RData::SOA(soa)) = (serial, &data) {
            data = RData::SOA(hickory_proto::rr::rdata::SOA::new(
                soa.mname().clone(),
                soa.rname().clone(),
                serial,
                soa.refresh(),
                soa.retry(),
                soa.expire(),
                soa.minimum(),
            ));
        }
        record.set_data(data);
        let text = match record.data() {
            // Hickory's Display prints TXT strings unquoted, which a zone file
            // parser splits at whitespace and re-joins without the spaces
            // ("v=spf1 mx -all" would be served as "v=spf1" "mx" "-all").
            // Write each character-string quoted and escaped instead.
            RData::TXT(txt) => {
                let strings: Vec<String> =
                    txt.txt_data().iter().map(|s| quote_txt_string(s)).collect();
                format!(
                    "{} {} IN TXT {}",
                    record.name(),
                    record.ttl(),
                    strings.join(" ")
                )
            }
            _ => record.to_string(),
        };
        // Safety gate: what we are about to publish must parse back to exactly
        // the data the user entered. Anything that does not round-trip is
        // refused rather than served corrupted.
        verify_roundtrip(&text, origin, record.data())?;
        Ok(text)
    }

    /// Validates that this record can be converted to a Hickory Record.
    /// Uses Hickory DNS APIs for all validation (zero custom logic).
    pub fn validate(&self) -> Result<()> {
        // Validate name through Hickory
        validate_record_name_input(&self.name).map_err(|err| anyhow!(err.to_string()))?;

        // Validate record type through Hickory
        validate_record_type(&self.record_type).map_err(|err| anyhow!(err.to_string()))?;

        // Validate TTL (simple numeric check)
        validate_ttl(self.ttl).map_err(|err| anyhow!(err.to_string()))?;

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

/// Ensure `name` is written as a fully-qualified name.
///
/// Relative names are qualified with the zone `origin`. Names that already
/// contain the zone domain (e.g. `ns1.uid0.ir` for origin `uid0.ir.`) are only
/// given a trailing dot rather than having the origin appended a second time.
fn absolutize_name(name: Name, origin: &Name) -> Name {
    if name.is_fqdn() {
        return name;
    }
    let ascii = name.to_string();
    let origin_str = origin.to_string();
    let origin_base = origin_str.trim_end_matches('.');
    if ascii == origin_base || ascii.ends_with(&format!(".{}", origin_base)) {
        Name::from_utf8(format!("{}.", ascii)).unwrap_or(name)
    } else {
        // append_domain consumes the name; fall back to a re-parsed absolute
        // name (the value was already validated) on failure
        name.append_domain(origin)
            .unwrap_or_else(|_| Name::from_utf8(format!("{}.", ascii)).expect("name parses"))
    }
}

/// Rewrites relative domain names embedded in RDATA to fully-qualified names.
///
/// This applies to every RDATA type that carries a host/domain name: SOA
/// (mname/rname), NS, CNAME, PTR, ANAME, MX, SRV and NAPTR.
fn absolutize_rdata(rdata: RData, origin: &Name) -> RData {
    use hickory_proto::rr::rdata::{ANAME, CNAME, MX, NAPTR, NS, PTR, SOA, SRV};

    match rdata {
        RData::SOA(soa) => RData::SOA(SOA::new(
            absolutize_name(soa.mname().clone(), origin),
            absolutize_name(soa.rname().clone(), origin),
            soa.serial(),
            soa.refresh(),
            soa.retry(),
            soa.expire(),
            soa.minimum(),
        )),
        RData::NS(ns) => RData::NS(NS(absolutize_name(ns.0, origin))),
        RData::CNAME(cname) => RData::CNAME(CNAME(absolutize_name(cname.0, origin))),
        RData::PTR(ptr) => RData::PTR(PTR(absolutize_name(ptr.0, origin))),
        RData::ANAME(aname) => RData::ANAME(ANAME(absolutize_name(aname.0, origin))),
        RData::MX(mx) => RData::MX(MX::new(
            mx.preference(),
            absolutize_name(mx.exchange().clone(), origin),
        )),
        RData::SRV(srv) => RData::SRV(SRV::new(
            srv.priority(),
            srv.weight(),
            srv.port(),
            absolutize_name(srv.target().clone(), origin),
        )),
        RData::NAPTR(naptr) => RData::NAPTR(NAPTR::new(
            naptr.order(),
            naptr.preference(),
            naptr.flags().to_vec().into_boxed_slice(),
            naptr.services().to_vec().into_boxed_slice(),
            naptr.regexp().to_vec().into_boxed_slice(),
            absolutize_name(naptr.replacement().clone(), origin),
        )),
        other => other,
    }
}

/// Quote one TXT character-string for a zone file (RFC 1035 §5.1 escapes).
pub fn quote_txt_string(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() + 2);
    out.push('"');
    for &b in bytes {
        match b {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            0x20..=0x7e => out.push(b as char),
            _ => out.push_str(&format!("\\{:03}", b)),
        }
    }
    out.push('"');
    out
}

/// Parse `text` back with Hickory's zone parser and require identical RDATA.
fn verify_roundtrip(text: &str, origin: &Name, expected: &RData) -> Result<()> {
    use hickory_proto::serialize::txt::Parser;
    let (_, parsed) = Parser::new(text.to_string(), None, Some(origin.clone()))
        .parse()
        .map_err(|e| anyhow!("serialized record does not parse back ({}): {}", e, text))?;
    let ok = parsed
        .values()
        .flat_map(|rs| rs.records_without_rrsigs())
        .any(|r| r.data() == expected);
    if ok {
        Ok(())
    } else {
        Err(anyhow!(
            "serialized record would not round-trip unchanged through the zone file: {}",
            text
        ))
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
                if priority > 0
                    && tokens
                        .next()
                        .map_or(true, |first| first.parse::<u16>().is_err())
                {
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
            "TXT" => {
                // Hickory's TXT parser treats an unquoted string as a
                // character-set and strips whitespace, so `v=spf1 mx -all`
                // would be persisted as `v=spf1mx-all`. Values already quoted
                // (one or more TXT segments) are passed through untouched.
                if trimmed.starts_with('"') || !trimmed.contains(char::is_whitespace) {
                    trimmed.to_string()
                } else {
                    format!("\"{}\"", trimmed)
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
        Self::write_validated_with_rename(zone_path, content, origin, |source, destination| {
            fs::rename(source, destination)
        })
    }

    fn write_validated_with_rename(
        zone_path: &Path,
        content: &str,
        origin: Option<&hickory_proto::rr::domain::Name>,
        rename: impl FnOnce(&Path, &Path) -> std::io::Result<()>,
    ) -> Result<()> {
        // Keep the full file name and append ".tmp": `with_extension` would
        // replace the last label of "zone.example.com" and make different
        // zones share one temporary file.
        let mut tmp_name = zone_path
            .file_name()
            .ok_or_else(|| anyhow!("zone path {:?} has no file name", zone_path))?
            .to_os_string();
        tmp_name.push(".tmp");
        let tmp_path = zone_path.with_file_name(tmp_name);

        debug!("Writing zone file to temporary location: {:?}", tmp_path);
        // A stale temporary file (e.g. left behind by a previous run owned by a
        // different uid) would make fs::write fail. Remove it before writing.
        let _ = fs::remove_file(&tmp_path);
        write_synced(&tmp_path, content.as_bytes())
            .with_context(|| format!("Failed to write zone file temp at {:?}", tmp_path))?;

        // Validate zone file using Hickory's parser - delegates to Hickory.
        // The existing (last known-good) zone file is untouched until this passes.
        if let Err(e) = validate_zone_file(&tmp_path, content, origin) {
            warn!(
                "Zone file validation failed, removing temporary file: {:?}",
                tmp_path
            );
            let _ = fs::remove_file(&tmp_path);
            return Err(e)
                .with_context(|| format!("Zone file validation failed at {:?}", tmp_path));
        }

        debug!(
            "Zone file validation passed, moving to final location: {:?}",
            zone_path
        );
        if let Err(e) = rename(&tmp_path, zone_path) {
            let _ = fs::remove_file(&tmp_path);
            return Err(e)
                .with_context(|| format!("Failed to rename temp zone file to {:?}", zone_path));
        }
        sync_parent_dir(zone_path);

        Ok(())
    }
}

/// Write `data` to `path` and fsync it so a crash right after the rename that
/// follows cannot leave an empty or truncated file under the final name.
pub fn write_synced(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = fs::File::create(path)?;
    f.write_all(data)?;
    f.sync_all()
}

/// Best-effort fsync of the directory containing `path` (makes the rename durable).
pub fn sync_parent_dir(path: &Path) {
    if let Some(dir) = path.parent() {
        if let Ok(d) = fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }
}

/// Escape a string for use inside a TOML basic string (`"..."`).
pub fn toml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\u{:04X}", c as u32))
            }
            c => out.push(c),
        }
    }
    out
}

/// TOML configuration builder for Hickory DNS named config.
pub struct TomlConfigBuilder {
    zones: Vec<TomlZone>,
    listen_ipv4: Vec<String>,
    listen_ipv6: Vec<String>,
    /// base directory for the DNS server (zone files and the config itself)
    directory: Option<String>,
    /// address of the DNS server's Prometheus exporter (`PROMETHEUS_LISTEN_ADDR`)
    prometheus_listen: Option<String>,
}

#[derive(Debug, Clone)]
struct TomlZone {
    zone: String,
    zone_type: String,
    zone_path: String,
    axfr_policy: String,
    axfr_allowed_peers: Vec<String>,
    geodns_enabled: bool,
    ecs: bool,
    geo_rules: Vec<TomlGeoRule>,
    /// DNSSEC signing keys: (private key file, algorithm name)
    keys: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
struct TomlGeoRule {
    match_type: String,
    match_value: String,
    target: String,
    weight: u32,
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
            listen_ipv6: Vec::new(),
            directory: None,
            prometheus_listen: None,
        }
    }

    /// Sets the DNS server's base configuration directory. Hickory watches this
    /// directory for zone file changes, so it must point at the directory where
    /// the generated zone files live.
    pub fn set_directory(&mut self, directory: &str) {
        self.directory = Some(directory.to_string());
    }

    /// Listen addresses from `LISTEN_ADDRS_IPV4` (default `0.0.0.0`) and
    /// `LISTEN_ADDRS_IPV6` (default none: IPv4 only, as before), both comma
    /// separated. Invalid entries are ignored with a warning.
    pub fn from_env() -> Self {
        fn list<T: std::str::FromStr>(var: &str) -> Option<Vec<String>> {
            let v = std::env::var(var).ok()?;
            let mut out = Vec::new();
            for item in v.split(',').map(str::trim).filter(|x| !x.is_empty()) {
                if item.parse::<T>().is_ok() {
                    out.push(item.to_string());
                } else {
                    warn!("ignoring invalid address {:?} in {}", item, var);
                }
            }
            Some(out)
        }
        let mut b = Self::new();
        if let Some(v4) = list::<std::net::Ipv4Addr>("LISTEN_ADDRS_IPV4") {
            if !v4.is_empty() {
                b.listen_ipv4 = v4;
            }
        }
        if let Some(v6) = list::<std::net::Ipv6Addr>("LISTEN_ADDRS_IPV6") {
            b.listen_ipv6 = v6;
        }
        if let Ok(v) = std::env::var("PROMETHEUS_LISTEN_ADDR") {
            let v = v.trim();
            if v.is_empty() {
            } else if v.parse::<std::net::SocketAddr>().is_ok() {
                b.prometheus_listen = Some(v.to_string());
            } else {
                warn!(
                    "ignoring invalid PROMETHEUS_LISTEN_ADDR {:?} (expected ip:port)",
                    v
                );
            }
        }
        b
    }

    /// Adds a zone to the configuration.
    pub fn add_zone(
        &mut self,
        zone: String,
        zone_path: String,
        geodns_enabled: bool,
        geo_rules: Vec<(
            String,
            String,
            String,
            u32,
            i32,
            bool,
            Option<String>,
            Option<String>,
        )>,
    ) -> Result<()> {
        let rules = geo_rules
            .into_iter()
            .map(
                |(
                    match_type,
                    match_value,
                    target,
                    weight,
                    priority,
                    enabled,
                    record_name,
                    record_type,
                )| {
                    TomlGeoRule {
                        match_type,
                        match_value,
                        target,
                        weight,
                        priority,
                        enabled,
                        record_name,
                        record_type,
                    }
                },
            )
            .collect();

        self.zones.push(TomlZone {
            zone,
            zone_type: "Primary".to_string(),
            zone_path,
            axfr_policy: "Deny".to_string(),
            axfr_allowed_peers: Vec::new(),
            geodns_enabled,
            ecs: false,
            geo_rules: rules,
            keys: Vec::new(),
        });

        Ok(())
    }

    /// Sign the most recently added zone with these key files.
    pub fn set_last_zone_keys(&mut self, keys: Vec<(String, String)>) {
        if let Some(z) = self.zones.last_mut() {
            z.keys = keys;
        }
    }

    /// Mark the most recently added zone as ECS-aware.
    pub fn set_last_zone_ecs(&mut self, ecs: bool) {
        if let Some(z) = self.zones.last_mut() {
            z.ecs = ecs;
        }
    }

    /// Set the transfer policy for the most recently added zone. Unknown
    /// values fail closed to Deny so database/config drift cannot expose AXFR.
    pub fn set_last_zone_axfr_policy(&mut self, policy: &str) {
        if let Some(z) = self.zones.last_mut() {
            z.axfr_policy = match policy.trim().to_ascii_lowercase().as_str() {
                "allowall" | "allow_all" | "allow-all" => "AllowAll".to_string(),
                "allowsigned" | "allow_signed" | "allow-signed" => "AllowSigned".to_string(),
                _ => "Deny".to_string(),
            };
        }
    }

    /// Set exact source addresses allowed to request AXFR for the last zone.
    /// Invalid values are discarded so malformed persisted state never opens
    /// an unintended peer range.
    pub fn set_last_zone_transfer_peers(&mut self, peers: Vec<String>) {
        if let Some(zone) = self.zones.last_mut() {
            zone.axfr_allowed_peers = peers
                .into_iter()
                .filter_map(|peer| peer.parse::<std::net::IpAddr>().ok())
                .map(|peer| peer.to_string())
                .collect();
            zone.axfr_allowed_peers.sort();
            zone.axfr_allowed_peers.dedup();
        }
    }

    /// Builds the final TOML string.
    pub fn build(&self) -> Result<String> {
        let mut result = String::new();
        if let Some(dir) = &self.directory {
            result.push_str(&format!("directory = \"{}\"\n", toml_escape(dir)));
        }
        result.push_str("listen_addrs_ipv4 = [");
        for (i, addr) in self.listen_ipv4.iter().enumerate() {
            if i > 0 {
                result.push_str(", ");
            }
            result.push('"');
            result.push_str(&toml_escape(addr));
            result.push('"');
        }
        result.push_str("]\n");
        if !self.listen_ipv6.is_empty() {
            result.push_str("listen_addrs_ipv6 = [");
            for (i, addr) in self.listen_ipv6.iter().enumerate() {
                if i > 0 {
                    result.push_str(", ");
                }
                result.push('"');
                result.push_str(&toml_escape(addr));
                result.push('"');
            }
            result.push_str("]\n");
        }
        if let Some(p) = &self.prometheus_listen {
            result.push_str(&format!(
                "prometheus_listen_addr = \"{}\"\n",
                toml_escape(p)
            ));
        }
        result.push('\n');

        for zone in &self.zones {
            result.push_str("[[zones]]\n");
            result.push_str(&format!("zone = \"{}\"\n", toml_escape(&zone.zone)));
            result.push_str(&format!(
                "zone_type = \"{}\"\n",
                toml_escape(&zone.zone_type)
            ));
            result.push_str(&format!("axfr_policy = \"{}\"\n", zone.axfr_policy));

            if zone.geodns_enabled {
                result.push_str(if zone.ecs {
                    "geodns = { enabled = true, ecs = true, rules = [\n"
                } else {
                    "geodns = { enabled = true, rules = [\n"
                });
                for rule in &zone.geo_rules {
                    result.push_str("  { ");
                    result.push_str(&format!(
                        "match_type = \"{}\", ",
                        toml_escape(&rule.match_type)
                    ));
                    result.push_str(&format!(
                        "match_value = \"{}\", ",
                        toml_escape(&rule.match_value)
                    ));
                    result.push_str(&format!("target = \"{}\", ", toml_escape(&rule.target)));
                    result.push_str(&format!("weight = {}, ", rule.weight));
                    result.push_str(&format!("priority = {}, ", rule.priority));
                    result.push_str(&format!("enabled = {}, ", rule.enabled));
                    if let Some(rn) = &rule.record_name {
                        result.push_str(&format!("record_name = \"{}\", ", toml_escape(rn)));
                    }
                    if let Some(rt) = &rule.record_type {
                        result.push_str(&format!("record_type = \"{}\", ", toml_escape(rt)));
                    }
                    result.push_str("},\n");
                }
                result.push_str("] }\n\n");
            }

            if !zone.keys.is_empty() {
                result.push_str("nx_proof_kind = \"nsec\"\nkeys = [\n");
                for (path, alg) in &zone.keys {
                    result.push_str(&format!(
                        "  {{ key_path = \"{}\", algorithm = \"{}\" }},\n",
                        toml_escape(path),
                        toml_escape(alg)
                    ));
                }
                result.push_str("]\n\n");
            }

            result.push_str("[[zones.stores]]\n");
            result.push_str("type = \"file\"\n");
            result.push_str(&format!(
                "zone_path = \"{}\"\n",
                toml_escape(&zone.zone_path)
            ));
            if !zone.axfr_allowed_peers.is_empty() {
                result.push_str("allowed_transfer_peers = [");
                for (index, peer) in zone.axfr_allowed_peers.iter().enumerate() {
                    if index > 0 {
                        result.push_str(", ");
                    }
                    result.push_str(&format!("\"{}\"", toml_escape(peer)));
                }
                result.push_str("]\n");
            }
            result.push('\n');
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
    fn atomic_zone_rename_failure_preserves_last_known_good_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("zone.example.com");
        let previous = "last known good";
        fs::write(&path, previous).unwrap();
        let origin = Name::from_utf8("example.com.").unwrap();
        let candidate = "example.com. 3600 IN SOA ns1.example.com. hostmaster.example.com. 1 3600 600 604800 300\nexample.com. 3600 IN NS ns1.example.com.\nwww.example.com. 300 IN A 192.0.2.55\n";
        let result = SafeZoneFileWriter::write_validated_with_rename(
            &path,
            candidate,
            Some(&origin),
            |_, _| Err(std::io::Error::other("injected atomic rename failure")),
        );
        assert!(result.is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), previous);
        assert!(!dir.path().join("zone.example.com.tmp").exists());
    }

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
    fn test_to_zone_string_with_origin_qualifies_soa_names() {
        let origin = Name::from_utf8("example.com.").unwrap();
        // SOA mname/rname entered relative (no trailing dot) must be written
        // fully-qualified so they are not doubled by the zone parser.
        let record = DnsRecordBuilder::from_db_fields(
            "example.com.".to_string(),
            "SOA".to_string(),
            "ns1.example.com hostmaster.example.com 2026080600 3600 3600 604800 3600".to_string(),
            3600,
            0,
        )
        .unwrap();
        let text = record.to_zone_string_with_origin(&origin).unwrap();
        assert!(
            text.contains("SOA ns1.example.com. hostmaster.example.com."),
            "was: {text}"
        );
        assert!(!text.contains(".example.com.example.com"));
    }

    #[test]
    fn test_to_zone_string_with_origin_keeps_absolute_soa() {
        let origin = Name::from_utf8("example.com.").unwrap();
        let record = DnsRecordBuilder::from_db_fields(
            "example.com.".to_string(),
            "SOA".to_string(),
            "ns1.example.com. hostmaster.example.com. 2024010101 3600 3600 604800 3600".to_string(),
            3600,
            0,
        )
        .unwrap();
        let text = record.to_zone_string_with_origin(&origin).unwrap();
        assert!(
            text.contains("SOA ns1.example.com. hostmaster.example.com."),
            "was: {text}"
        );
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
        builder.set_directory("/etc/hickory");
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
        assert!(toml_str.contains("axfr_policy = \"Deny\""));
        assert!(toml_str.contains("directory = \"/etc/hickory\""));
        assert!(toml_str.contains("listen_addrs_ipv4"));
    }

    #[test]
    fn axfr_policy_is_per_zone_and_unknown_values_fail_closed() {
        let mut builder = TomlConfigBuilder::new();
        builder
            .add_zone("one.example".into(), "/z/one".into(), false, vec![])
            .unwrap();
        builder.set_last_zone_axfr_policy("AllowAll");
        builder.set_last_zone_transfer_peers(vec![
            "192.0.2.7".into(),
            "2001:db8::7".into(),
            "not-an-ip".into(),
        ]);
        builder
            .add_zone("two.example".into(), "/z/two".into(), false, vec![])
            .unwrap();
        builder.set_last_zone_axfr_policy("untrusted-value\n[[zones]]");
        let output = builder.build().unwrap();
        assert!(output.contains(
            "zone = \"one.example\"\nzone_type = \"Primary\"\naxfr_policy = \"AllowAll\""
        ));
        assert!(output.contains(
            "zone_path = \"/z/one\"\nallowed_transfer_peers = [\"192.0.2.7\", \"2001:db8::7\"]"
        ));
        assert!(
            output.contains(
                "zone = \"two.example\"\nzone_type = \"Primary\"\naxfr_policy = \"Deny\""
            )
        );
        assert_eq!(output.matches("axfr_policy =").count(), 2);
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
        assert!(
            record.validate().is_err(),
            "Hickory should reject invalid IPv6"
        );
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
        assert!(
            record.validate().is_err(),
            "Hickory should reject invalid record type"
        );
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
        assert!(
            record.validate().is_err(),
            "Invalid domain names should be rejected by Hickory"
        );
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
        assert!(
            result.is_err(),
            "Builder should validate through Hickory and reject invalid IPv6"
        );
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
        assert!(
            result.is_ok(),
            "MX record with priority should validate through Hickory"
        );
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
        assert!(
            record.validate().is_err(),
            "Hickory should reject invalid SOA format"
        );
    }
}

#[cfg(test)]
mod roundtrip_tests {
    use super::*;
    use hickory_proto::serialize::txt::Parser;

    fn render(name: &str, t: &str, v: &str, prio: i32) -> anyhow::Result<String> {
        let origin = Name::from_utf8("example.com.").unwrap();
        DnsRecordBuilder::from_db_fields(name.to_string(), t.to_string(), v.to_string(), 300, prio)?
            .to_zone_string_with_origin(&origin)
    }

    fn txt_strings(text: &str) -> Vec<Vec<u8>> {
        let origin = Name::from_utf8("example.com.").unwrap();
        let (_, recs) = Parser::new(text.to_string(), None, Some(origin))
            .parse()
            .unwrap();
        for rs in recs.values() {
            for r in rs.records_without_rrsigs() {
                if let RData::TXT(t) = r.data() {
                    return t.txt_data().iter().map(|b| b.to_vec()).collect();
                }
            }
        }
        panic!("no TXT in {text}");
    }

    #[test]
    fn txt_with_spaces_is_one_string_not_split() {
        // used to be served as three strings "v=spf1" "mx" "-all"
        let text = render("t.example.com.", "TXT", "v=spf1 mx -all", 0).unwrap();
        assert_eq!(
            txt_strings(&text),
            vec![b"v=spf1 mx -all".to_vec()],
            "{text}"
        );
        let text = render("t.example.com.", "TXT", "\"v=spf1 mx -all\"", 0).unwrap();
        assert_eq!(
            txt_strings(&text),
            vec![b"v=spf1 mx -all".to_vec()],
            "{text}"
        );
    }

    #[test]
    fn txt_quotes_backslashes_semicolons_and_segments_survive() {
        let text = render("t.example.com.", "TXT", "\"say \\\"hi\\\" \\\\ ; ok\"", 0).unwrap();
        assert_eq!(
            txt_strings(&text),
            vec![b"say \"hi\" \\ ; ok".to_vec()],
            "{text}"
        );
        let text = render("t.example.com.", "TXT", "\"seg one\" \"seg two\"", 0).unwrap();
        assert_eq!(
            txt_strings(&text),
            vec![b"seg one".to_vec(), b"seg two".to_vec()],
            "{text}"
        );
        let dkim = "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC";
        let text = render("sel._domainkey.example.com.", "TXT", dkim, 0).unwrap();
        assert_eq!(txt_strings(&text), vec![dkim.as_bytes().to_vec()], "{text}");
    }

    #[test]
    fn common_record_types_round_trip() {
        for (n, t, v, p) in [
            ("a.example.com.", "A", "192.0.2.1", 0),
            ("a.example.com.", "AAAA", "2001:db8::1", 0),
            ("example.com.", "MX", "mail.example.com.", 10),
            ("w.example.com.", "CNAME", "x.example.com.", 0),
            (
                "_sip._tcp.example.com.",
                "SRV",
                "2 5060 sip.example.com.",
                1,
            ),
            ("c.example.com.", "CAA", "0 issue \"letsencrypt.org\"", 0),
            (
                "tl.example.com.",
                "TLSA",
                "3 1 1 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                0,
            ),
        ] {
            render(n, t, v, p).unwrap_or_else(|e| panic!("{t} {v}: {e:#}"));
        }
    }

    #[test]
    fn toml_escape_neutralises_metacharacters() {
        assert_eq!(toml_escape("a\"b"), "a\\\"b");
        assert_eq!(toml_escape("a\\b"), "a\\\\b");
        assert_eq!(toml_escape("a\nb"), "a\\nb");
        let mut b = TomlConfigBuilder::new();
        b.add_zone(
            "evil.com".into(),
            "/z/zone.evil.com".into(),
            true,
            vec![(
                "country".into(),
                "US\"\n[[zones]]\nzone=\"pwn\"".into(),
                "1.1.1.1".into(),
                1,
                0,
                true,
                None,
                None,
            )],
        )
        .unwrap();
        let out = b.build().unwrap();
        assert_eq!(out.matches("[[zones]]\n").count(), 1, "{out}");
        assert!(!out.contains("\nzone=\"pwn\""), "{out}");
    }
}
