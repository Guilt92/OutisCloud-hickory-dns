use maxminddb::Reader;
use std::net::{IpAddr, Ipv6Addr};

pub struct GeoDB {
    reader: std::sync::Arc<Reader<Vec<u8>>>,
}

impl Clone for GeoDB {
    fn clone(&self) -> Self {
        Self {
            reader: self.reader.clone(),
        }
    }
}

/// Map IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) to plain IPv4 so that a
/// dual-stack listener reports the same location as a native IPv4 socket.
fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        other => other,
    }
}

/// Addresses that can never have a meaningful geographic location.
fn is_non_geolocatable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
        }
        IpAddr::V6(v6) => {
            let seg0 = v6.segments()[0];
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // unique local fc00::/7 and link local fe80::/10
                || (seg0 & 0xfe00) == 0xfc00
                || (seg0 & 0xffc0) == 0xfe80
                || v6 == Ipv6Addr::LOCALHOST
        }
    }
}

/// Result of [`GeoDB::classify`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GeoClass {
    Reserved,
    Country(String),
    Unknown,
}

/// Non-geolocatable addresses plus ranges that are never real client locations (documentation, CGNAT, reserved).
pub fn is_reserved(ip: IpAddr) -> bool {
    let ip = normalize_ip(ip);
    if is_non_geolocatable(ip) {
        return true;
    }
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            (o[0] == 100 && (o[1] & 0xc0) == 64)                       // 100.64.0.0/10 CGNAT
                || (o[0] == 192 && o[1] == 0 && o[2] == 2)              // TEST-NET-1
                || (o[0] == 198 && o[1] == 51 && o[2] == 100)           // TEST-NET-2
                || (o[0] == 203 && o[1] == 0 && o[2] == 113)            // TEST-NET-3
                || (o[0] == 198 && (o[1] & 0xfe) == 18)                 // benchmarking 198.18/15
                || o[0] >= 240 // reserved 240/4
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            (s[0] == 0x2001 && s[1] == 0x0db8)
                || (s[0] == 0x0100 && s[1] == 0 && s[2] == 0 && s[3] == 0) // documentation, discard
        }
    }
}

impl GeoDB {
    pub fn open_from_bytes(bytes: Vec<u8>) -> Result<Self, maxminddb::MaxMindDbError> {
        let reader = Reader::from_source(bytes)?;
        Ok(Self {
            reader: std::sync::Arc::new(reader),
        })
    }

    /// Unix time at which MaxMind built this database (staleness checks).
    pub fn build_epoch(&self) -> u64 {
        self.reader.metadata.build_epoch
    }

    /// Classify a client address for analytics WITHOUT inventing a location: `Reserved` for addresses that can never
    /// be located (private, loopback, link-local, multicast, documentation, CGNAT, reserved), `Country` when the
    /// database knows the address, `Unknown` when the database has no entry for a routable address.
    pub fn classify(&self, ip: IpAddr) -> GeoClass {
        let ip = normalize_ip(ip);
        if is_reserved(ip) {
            return GeoClass::Reserved;
        }
        match self.country(ip) {
            Some(c) => GeoClass::Country(c),
            None => GeoClass::Unknown,
        }
    }

    /// The MaxMind `database_type` string (for example `GeoLite2-Country` or
    /// `GeoLite2-City`). Region matching needs a City database.
    pub fn database_type(&self) -> &str {
        &self.reader.metadata.database_type
    }

    fn has_subdivisions(&self) -> bool {
        let t = self.database_type();
        t.contains("City") || t.contains("Enterprise")
    }

    /// ISO 3166-1 alpha-2 country code of `ip`.
    pub fn country(&self, ip: IpAddr) -> Option<String> {
        let ip = normalize_ip(ip);
        if is_non_geolocatable(ip) {
            return None;
        }
        let rec: maxminddb::geoip2::Country = self.reader.lookup(ip).ok()?.decode().ok()??;
        rec.country.iso_code.map(|s| s.to_string())
    }

    /// Two letter continent code of `ip` (`AF`, `AN`, `AS`, `EU`, `NA`, `OC`, `SA`).
    pub fn continent(&self, ip: IpAddr) -> Option<String> {
        let ip = normalize_ip(ip);
        if is_non_geolocatable(ip) {
            return None;
        }
        let rec: maxminddb::geoip2::Country = self.reader.lookup(ip).ok()?.decode().ok()??;
        rec.continent.code.map(|s| s.to_string())
    }

    /// English city name of `ip` (City/Enterprise databases only).
    pub fn city(&self, ip: IpAddr) -> Option<String> {
        if !self.has_subdivisions() {
            return None;
        }
        let ip = normalize_ip(ip);
        if is_non_geolocatable(ip) {
            return None;
        }
        let rec: maxminddb::geoip2::City = self.reader.lookup(ip).ok()?.decode().ok()??;
        let name = rec.city.names.english?;
        let cc = rec.country.iso_code?;
        Some(format!("{}:{}", cc, name))
    }

    /// ISO 3166-2 subdivision of `ip` in `CC-SUB` form (for example `US-CA`).
    /// Returns `None` when the loaded database carries no subdivision data
    /// (the Country editions do not).
    pub fn region(&self, ip: IpAddr) -> Option<String> {
        if !self.has_subdivisions() {
            return None;
        }
        let ip = normalize_ip(ip);
        if is_non_geolocatable(ip) {
            return None;
        }
        let rec: maxminddb::geoip2::City = self.reader.lookup(ip).ok()?.decode().ok()??;
        let cc = rec.country.iso_code?;
        let sub = rec
            .subdivisions
            .into_iter()
            .next()
            .and_then(|s| s.iso_code)?;
        Some(format!("{}-{}", cc, sub))
    }
}

/// GeoDNS rule for matching and routing based on geographic criteria.
#[derive(Clone, Debug)]
pub struct GeoRule {
    pub id: String,
    /// "country", "region", "continent", "default" / "fallback"
    pub match_type: String,
    /// country: ISO 3166-1 alpha-2 (`US`); continent: `EU`, `NA`, ...;
    /// region: ISO 3166-2 (`US-CA`); ignored for "default".
    pub match_value: String,
    pub target: String, // IP address to return
    pub priority: i32,  // higher values take precedence
    pub enabled: bool,  // rule disabled if false
    // optional record-level matching; if both are None the rule applies to whole zone
    pub record_name: Option<String>,
    pub record_type: Option<String>,
}

/// Total, deterministic ordering of rules: highest priority first, ties broken
/// by rule content (never by insertion/database order or random ids) so every
/// replica evaluating the same rule set returns the same answer.
fn rule_order(a: &GeoRule, b: &GeoRule) -> std::cmp::Ordering {
    b.priority
        .cmp(&a.priority)
        // at equal priority a rule scoped to a record name beats a zone-wide rule,
        // and the most specific location wins: city > region > country > continent
        .then_with(|| is_zone_wide(a).cmp(&is_zone_wide(b)))
        .then_with(|| specificity(&a.match_type).cmp(&specificity(&b.match_type)))
        .then_with(|| a.match_type.cmp(&b.match_type))
        .then_with(|| a.match_value.cmp(&b.match_value))
        .then_with(|| a.record_name.cmp(&b.record_name))
        .then_with(|| a.record_type.cmp(&b.record_type))
        .then_with(|| a.target.cmp(&b.target))
}

fn is_zone_wide(r: &GeoRule) -> bool {
    r.record_name
        .as_deref()
        .map_or(true, |n| n.trim().is_empty())
}

/// Lower is more specific.
fn specificity(match_type: &str) -> u8 {
    match match_type {
        "city" => 0,
        "region" => 1,
        "country" => 2,
        "continent" => 3,
        "default" | "fallback" => 5,
        _ => 4,
    }
}

/// Normalise a DNS name for comparison: lower-case, no trailing dot.
fn norm_name(s: &str) -> String {
    s.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Does a rule's `record_name` select the queried name?
///
/// Rules are stored the way operators type them: `@` (zone apex), a relative
/// label such as `www`, or a fully-qualified name. `origin` is the zone apex
/// without trailing dot.
fn record_name_matches(rule_name: &str, query_name: &str, origin: Option<&str>) -> bool {
    let rn = norm_name(rule_name);
    let qn = norm_name(query_name);
    match origin.map(norm_name) {
        Some(o) => {
            let fq = if rn == "@" {
                o.clone()
            } else if rn == o || rn.ends_with(&format!(".{}", o)) {
                rn
            } else {
                format!("{}.{}", rn, o)
            };
            fq == qn
        }
        None => rn == qn,
    }
}

/// GeoRule engine: evaluates rules and returns best target based on client IP
pub struct GeoRuleEngine {
    rules: Vec<GeoRule>,
    db: Option<GeoDB>,
}

impl GeoRuleEngine {
    /// Create a new GeoRule engine, optionally with a GeoDB
    pub fn new(db: Option<GeoDB>) -> Self {
        Self {
            rules: Vec::new(),
            db,
        }
    }

    /// Add a rule to the engine
    pub fn add_rule(&mut self, rule: GeoRule) {
        self.rules.push(rule);
        self.rules.sort_by(rule_order);
    }

    /// Set all rules at once
    pub fn set_rules(&mut self, mut rules: Vec<GeoRule>) {
        // filter out disabled rules and sort deterministically
        rules.retain(|r| r.enabled);
        rules.sort_by(rule_order);
        self.rules = rules;
    }

    /// Evaluate rules for a client IP and optional query context (name/type).
    /// Returns Some(target) if a rule matches, None if no match (use default).
    /// `query_name` is compared with `record_name` literally (case-insensitive,
    /// trailing dot ignored); use [`evaluate_in_zone`](Self::evaluate_in_zone)
    /// to resolve relative rule names against a zone apex.
    pub fn evaluate(
        &self,
        client_ip: IpAddr,
        query_name: Option<&str>,
        query_type: Option<&str>,
    ) -> Option<String> {
        self.evaluate_inner(client_ip, query_name, query_type, None, false)
    }

    /// Like [`evaluate`](Self::evaluate) but relative / apex (`@`) rule names are
    /// resolved against `origin` before being compared with the queried name.
    pub fn evaluate_in_zone(
        &self,
        client_ip: IpAddr,
        query_name: &str,
        query_type: &str,
        origin: &str,
    ) -> Option<String> {
        self.evaluate_inner(
            client_ip,
            Some(query_name),
            Some(query_type),
            Some(origin),
            false,
        )
    }

    /// Like [`evaluate_in_zone`](Self::evaluate_in_zone), but when the queried
    /// name does not exist in the zone (`name_exists == false`) only rules that
    /// name a specific `record_name` are considered. Zone-wide rules never
    /// invent answers for names the zone does not contain.
    pub fn evaluate_in_zone_checked(
        &self,
        client_ip: IpAddr,
        query_name: &str,
        query_type: &str,
        origin: &str,
        name_exists: bool,
    ) -> Option<String> {
        self.evaluate_inner(
            client_ip,
            Some(query_name),
            Some(query_type),
            Some(origin),
            !name_exists,
        )
    }

    fn evaluate_inner(
        &self,
        client_ip: IpAddr,
        query_name: Option<&str>,
        query_type: Option<&str>,
        origin: Option<&str>,
        scoped_only: bool,
    ) -> Option<String> {
        let client_ip = normalize_ip(client_ip);
        // Look the client up lazily and only once per evaluation.
        let country = self.db.as_ref().and_then(|db| db.country(client_ip));
        let continent = self.db.as_ref().and_then(|db| db.continent(client_ip));
        let region = self.db.as_ref().and_then(|db| db.region(client_ip));
        let city = self.db.as_ref().and_then(|db| db.city(client_ip));

        let matches = |rule: &GeoRule| -> bool {
            if !rule.enabled {
                return false;
            }
            if scoped_only
                && rule
                    .record_name
                    .as_deref()
                    .map_or(true, |n| n.trim().is_empty())
            {
                return false;
            }
            if let (Some(qn), Some(rn)) = (query_name, rule.record_name.as_deref()) {
                if !rn.trim().is_empty() && !record_name_matches(rn, qn, origin) {
                    return false;
                }
            }
            if let (Some(qt), Some(rt)) = (query_type, rule.record_type.as_deref()) {
                if !rt.trim().is_empty() && !rt.eq_ignore_ascii_case(qt) {
                    return false;
                }
            }
            let want = rule.match_value.trim();
            match rule.match_type.as_str() {
                "country" => country
                    .as_deref()
                    .map_or(false, |c| want.eq_ignore_ascii_case(c)),
                "continent" => continent
                    .as_deref()
                    .map_or(false, |c| want.eq_ignore_ascii_case(c)),
                "region" => {
                    // ISO 3166-2 (`US-CA`) needs a City database. For backward
                    // compatibility a bare country code keeps matching the
                    // client's country, which is what this type did before
                    // subdivision data was consulted.
                    region
                        .as_deref()
                        .map_or(false, |r| want.eq_ignore_ascii_case(r))
                        || country
                            .as_deref()
                            .map_or(false, |c| want.eq_ignore_ascii_case(c))
                }
                // `CC:City Name` (for example `US:Los Angeles`) or just the city
                // name; needs a City database
                "city" => city.as_deref().map_or(false, |c| {
                    want.eq_ignore_ascii_case(c)
                        || c.split_once(':')
                            .map_or(false, |(_, n)| want.eq_ignore_ascii_case(n))
                }),
                // fallback rule always matches when reached, including for
                // clients with no geographic information (private, reserved or
                // unlisted addresses).
                "default" | "fallback" => true,
                _ => false,
            }
        };

        // rules are kept sorted in priority order
        self.rules
            .iter()
            .find(|r| matches(r))
            .map(|r| r.target.clone())
    }

    /// Get all rules
    pub fn rules(&self) -> &[GeoRule] {
        &self.rules
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The tests run against the real GeoLite2-Country dataset shipped in
    /// `deploy/dns`; they fail loudly (rather than silently passing) if it is
    /// missing or unreadable.
    fn real_db() -> GeoDB {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../deploy/dns/GeoLite2-Country.mmdb"
        );
        let bytes =
            std::fs::read(path).unwrap_or_else(|e| panic!("GeoIP dataset {path} unreadable: {e}"));
        GeoDB::open_from_bytes(bytes).expect("valid mmdb")
    }

    fn rule(
        id: &str,
        mtype: &str,
        mval: &str,
        target: &str,
        priority: i32,
        enabled: bool,
    ) -> GeoRule {
        GeoRule {
            id: id.to_string(),
            match_type: mtype.to_string(),
            match_value: mval.to_string(),
            target: target.to_string(),
            priority,
            enabled,
            record_name: None,
            record_type: None,
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn engine(rules: Vec<GeoRule>) -> GeoRuleEngine {
        let mut e = GeoRuleEngine::new(Some(real_db()));
        e.set_rules(rules);
        e
    }

    #[test]
    fn real_dataset_country_continent_ipv4_and_ipv6() {
        let db = real_db();
        assert_eq!(db.country(ip("8.8.8.8")).as_deref(), Some("US"));
        assert_eq!(db.continent(ip("8.8.8.8")).as_deref(), Some("NA"));
        assert_eq!(db.country(ip("5.9.0.1")).as_deref(), Some("DE"));
        assert_eq!(db.continent(ip("5.9.0.1")).as_deref(), Some("EU"));
        assert_eq!(db.country(ip("41.0.0.1")).as_deref(), Some("ZA"));
        assert_eq!(db.continent(ip("41.0.0.1")).as_deref(), Some("AF"));
        assert_eq!(db.country(ip("200.160.2.3")).as_deref(), Some("BR"));
        assert_eq!(db.continent(ip("200.160.2.3")).as_deref(), Some("SA"));
        // IPv6
        assert_eq!(
            db.country(ip("2001:4860:4860::8888")).as_deref(),
            Some("US")
        );
        assert_eq!(
            db.country(ip("2a00:1450:4001:81b::200e")).as_deref(),
            Some("DE")
        );
        assert_eq!(
            db.continent(ip("2a00:1450:4001:81b::200e")).as_deref(),
            Some("EU")
        );
        // IPv4-mapped IPv6 behaves like the embedded IPv4 address
        assert_eq!(db.country(ip("::ffff:8.8.8.8")).as_deref(), Some("US"));
    }

    #[test]
    fn non_public_addresses_have_no_location() {
        let db = real_db();
        for a in [
            "10.0.0.1",
            "192.168.1.1",
            "172.16.5.5",
            "127.0.0.1",
            "169.254.1.1",
            "224.0.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "fe80::1",
            "fd00::1",
            "::1",
            "::",
            "ff02::1",
        ] {
            assert_eq!(db.country(ip(a)), None, "{a}");
            assert_eq!(db.continent(ip(a)), None, "{a}");
        }
        // a public address that is absent from the dataset (anycast) is also unknown
        assert_eq!(db.country(ip("1.1.1.1")), None);
    }

    #[test]
    fn country_rule_matches_only_that_country() {
        let e = engine(vec![rule("us", "country", "US", "10.1.1.1", 0, true)]);
        assert_eq!(
            e.evaluate(ip("8.8.8.8"), None, None).as_deref(),
            Some("10.1.1.1")
        );
        assert_eq!(
            e.evaluate(ip("2001:4860:4860::8888"), None, None)
                .as_deref(),
            Some("10.1.1.1")
        );
        assert_eq!(e.evaluate(ip("5.9.0.1"), None, None), None);
        // lower-case configuration still matches
        let e = engine(vec![rule("us", "country", "us", "10.1.1.1", 0, true)]);
        assert_eq!(
            e.evaluate(ip("8.8.8.8"), None, None).as_deref(),
            Some("10.1.1.1")
        );
    }

    #[test]
    fn continent_rule_matches_every_country_on_the_continent() {
        let e = engine(vec![rule("eu", "continent", "EU", "10.2.2.2", 0, true)]);
        assert_eq!(
            e.evaluate(ip("5.9.0.1"), None, None).as_deref(),
            Some("10.2.2.2")
        ); // DE
        assert_eq!(
            e.evaluate(ip("80.246.31.97"), None, None).as_deref(),
            Some("10.2.2.2")
        ); // LV
        assert_eq!(e.evaluate(ip("8.8.8.8"), None, None), None); // US
        assert_eq!(e.evaluate(ip("41.0.0.1"), None, None), None); // ZA
    }

    #[test]
    fn region_with_country_dataset_cannot_match_subdivisions() {
        // GeoLite2-Country has no subdivision data: a real "US-CA" rule must
        // not match (and must not pretend to), while the legacy behaviour of a
        // bare country code is preserved.
        let e = engine(vec![rule("ca", "region", "US-CA", "10.3.3.3", 0, true)]);
        assert_eq!(e.evaluate(ip("8.8.8.8"), None, None), None);
        let e = engine(vec![rule("legacy", "region", "US", "10.3.3.3", 0, true)]);
        assert_eq!(
            e.evaluate(ip("8.8.8.8"), None, None).as_deref(),
            Some("10.3.3.3")
        );
    }

    #[test]
    fn city_rules_cannot_match_with_a_country_database() {
        // GeoLite2-Country carries no city data: a city rule must stay silent
        // (and the default rule must take over) instead of guessing.
        let e = engine(vec![
            rule("la", "city", "US:Los Angeles", "10.4.4.4", 10, true),
            rule("dflt", "default", "", "10.0.0.9", 0, true),
        ]);
        assert_eq!(real_db().city(ip("8.8.8.8")), None);
        assert_eq!(
            e.evaluate(ip("8.8.8.8"), None, None).as_deref(),
            Some("10.0.0.9")
        );
    }

    #[test]
    fn priority_and_specificity_ordering() {
        let e = engine(vec![
            rule("cont", "continent", "NA", "10.0.0.2", 5, true),
            rule("ctry", "country", "US", "10.0.0.1", 10, true),
            rule("dflt", "default", "", "10.0.0.9", 0, true),
        ]);
        assert_eq!(
            e.evaluate(ip("8.8.8.8"), None, None).as_deref(),
            Some("10.0.0.1")
        );
        assert_eq!(
            e.evaluate(ip("5.9.0.1"), None, None).as_deref(),
            Some("10.0.0.9")
        );
    }

    #[test]
    fn equal_priority_is_deterministic_regardless_of_input_order() {
        let a = rule("a", "country", "US", "10.0.0.5", 1, true);
        let b = rule("b", "country", "US", "10.0.0.4", 1, true);
        let e1 = engine(vec![a.clone(), b.clone()]);
        let e2 = engine(vec![b, a]);
        assert_eq!(
            e1.evaluate(ip("8.8.8.8"), None, None),
            e2.evaluate(ip("8.8.8.8"), None, None)
        );
    }

    #[test]
    fn disabled_rules_are_ignored() {
        let mut e = GeoRuleEngine::new(Some(real_db()));
        e.add_rule(rule("r1", "country", "US", "1.1.1.1", 9, false));
        e.add_rule(rule("r2", "country", "US", "2.2.2.2", 0, true));
        // add_rule keeps disabled rules but evaluation skips them
        assert_eq!(
            e.evaluate(ip("8.8.8.8"), None, None).as_deref(),
            Some("2.2.2.2")
        );
    }

    #[test]
    fn fallback_applies_to_unknown_private_and_unlisted_clients() {
        let e = engine(vec![
            rule("us", "country", "US", "10.0.0.1", 10, true),
            rule("dflt", "default", "", "10.0.0.9", 0, true),
        ]);
        for a in [
            "10.0.0.1",
            "192.168.0.7",
            "::1",
            "fd00::5",
            "1.1.1.1",
            "5.9.0.1",
        ] {
            assert_eq!(
                e.evaluate(ip(a), None, None).as_deref(),
                Some("10.0.0.9"),
                "{a}"
            );
        }
    }

    #[test]
    fn no_database_means_only_default_rules_match() {
        let mut e = GeoRuleEngine::new(None);
        e.set_rules(vec![
            rule("us", "country", "US", "10.0.0.1", 10, true),
            rule("dflt", "default", "", "10.0.0.9", 0, true),
        ]);
        assert_eq!(
            e.evaluate(ip("8.8.8.8"), None, None).as_deref(),
            Some("10.0.0.9")
        );
        let mut e = GeoRuleEngine::new(None);
        e.set_rules(vec![rule("us", "country", "US", "10.0.0.1", 10, true)]);
        assert_eq!(e.evaluate(ip("8.8.8.8"), None, None), None);
    }

    #[test]
    fn record_specific_matching_resolves_names_against_the_zone() {
        let mut r = rule("r1", "country", "US", "1.1.1.1", 0, true);
        r.record_name = Some("www".to_string());
        r.record_type = Some("A".to_string());
        let e = engine(vec![r]);
        // literal comparison (legacy API)
        assert_eq!(
            e.evaluate(ip("8.8.8.8"), Some("www"), Some("A")).as_deref(),
            Some("1.1.1.1")
        );
        assert_eq!(e.evaluate(ip("8.8.8.8"), Some("other"), Some("A")), None);
        assert_eq!(e.evaluate(ip("8.8.8.8"), Some("www"), Some("AAAA")), None);
        // zone-aware API: the server hands over the fully-qualified query name
        let o = "example.com";
        assert_eq!(
            e.evaluate_in_zone(ip("8.8.8.8"), "www.example.com.", "A", o)
                .as_deref(),
            Some("1.1.1.1")
        );
        assert_eq!(
            e.evaluate_in_zone(ip("8.8.8.8"), "WWW.Example.COM.", "a", o)
                .as_deref(),
            Some("1.1.1.1")
        );
        assert_eq!(
            e.evaluate_in_zone(ip("8.8.8.8"), "mail.example.com.", "A", o),
            None
        );
        assert_eq!(
            e.evaluate_in_zone(ip("8.8.8.8"), "example.com.", "A", o),
            None
        );
    }

    #[test]
    fn apex_and_absolute_record_names() {
        let mut apex = rule("apex", "default", "", "1.1.1.1", 0, true);
        apex.record_name = Some("@".to_string());
        let e = engine(vec![apex]);
        assert!(
            e.evaluate_in_zone(ip("8.8.8.8"), "example.com.", "A", "example.com")
                .is_some()
        );
        assert!(
            e.evaluate_in_zone(ip("8.8.8.8"), "www.example.com.", "A", "example.com")
                .is_none()
        );
        let mut abs = rule("abs", "default", "", "1.1.1.1", 0, true);
        abs.record_name = Some("api.example.com.".to_string());
        let e = engine(vec![abs]);
        assert!(
            e.evaluate_in_zone(ip("8.8.8.8"), "api.example.com.", "A", "example.com")
                .is_some()
        );
    }

    #[test]
    fn zone_wide_rules_do_not_answer_for_missing_names() {
        let mut scoped = rule("s", "default", "", "10.0.0.2", 5, true);
        scoped.record_name = Some("api".into());
        let e = engine(vec![
            rule("wide", "country", "US", "10.0.0.1", 0, true),
            scoped,
        ]);
        let us = ip("8.8.8.8");
        // existing name: both kinds of rule apply (wide has lower priority than scoped here)
        assert_eq!(
            e.evaluate_in_zone_checked(us, "www.example.com.", "A", "example.com", true)
                .as_deref(),
            Some("10.0.0.1")
        );
        // missing name: the zone-wide rule must stay silent
        assert_eq!(
            e.evaluate_in_zone_checked(us, "nope.example.com.", "A", "example.com", false),
            None
        );
        // an explicitly named rule still applies even if the zone has no static record
        assert_eq!(
            e.evaluate_in_zone_checked(us, "api.example.com.", "A", "example.com", false)
                .as_deref(),
            Some("10.0.0.2")
        );
    }

    #[test]
    fn ipv4_mapped_clients_are_geolocated_as_ipv4() {
        let e = engine(vec![rule("us", "country", "US", "10.0.0.1", 0, true)]);
        assert_eq!(
            e.evaluate(ip("::ffff:8.8.8.8"), None, None).as_deref(),
            Some("10.0.0.1")
        );
    }

    // ---- City / region matching against a real MaxMind City database -------
    // MaxMind publishes small open test databases (MaxMind-DB repository) that
    // contain real City/subdivision structures. Point GEOIP_CITY_TEST_DB at
    // GeoLite2-City-Test.mmdb (or GeoIP2-City-Test.mmdb, or a full GeoLite2-City).
    fn city_db() -> Option<GeoDB> {
        match std::env::var("GEOIP_CITY_TEST_DB") {
            Ok(p) => Some(
                GeoDB::open_from_bytes(std::fs::read(&p).unwrap_or_else(|e| panic!("{p}: {e}")))
                    .expect("valid mmdb"),
            ),
            Err(_) => {
                eprintln!("SKIPPED: GEOIP_CITY_TEST_DB not set");
                None
            }
        }
    }

    fn city_engine(db: GeoDB, rules: Vec<GeoRule>) -> GeoRuleEngine {
        let mut e = GeoRuleEngine::new(Some(db));
        e.set_rules(rules);
        e
    }

    #[test]
    fn city_database_exposes_country_continent_region_and_city() {
        let Some(db) = city_db() else { return };
        assert!(db.database_type().contains("City"));
        // London (test data): GB / EU / England / London
        let london = ip("81.2.69.142");
        assert_eq!(db.country(london).as_deref(), Some("GB"));
        assert_eq!(db.continent(london).as_deref(), Some("EU"));
        assert_eq!(db.region(london).as_deref(), Some("GB-ENG"));
        assert_eq!(db.city(london).as_deref(), Some("GB:London"));
        // Milton, Washington (test data)
        let milton = ip("216.160.83.56");
        assert_eq!(db.country(milton).as_deref(), Some("US"));
        assert_eq!(db.region(milton).as_deref(), Some("US-WA"));
        assert_eq!(db.city(milton).as_deref(), Some("US:Milton"));
        // Non-public addresses still have no location
        assert_eq!(db.city(ip("10.1.2.3")), None);
        assert_eq!(db.region(ip("192.168.0.1")), None);
    }

    #[test]
    fn city_and_region_rules_match_and_are_the_most_specific() {
        let Some(db) = city_db() else { return };
        let e = city_engine(
            db,
            vec![
                rule("country", "country", "GB", "10.0.0.1", 0, true),
                rule("continent", "continent", "EU", "10.0.0.2", 0, true),
                rule("region", "region", "GB-ENG", "10.0.0.3", 0, true),
                rule("city", "city", "GB:London", "10.0.0.4", 0, true),
            ],
        );
        // same priority: city beats region beats country beats continent
        assert_eq!(
            e.evaluate(ip("81.2.69.142"), None, None).as_deref(),
            Some("10.0.0.4")
        );
        // England but not London -> region rule
        assert_eq!(
            e.evaluate(ip("2.125.160.216"), None, None).as_deref(),
            Some("10.0.0.3")
        );
        // Sweden is in Europe only -> continent rule
        assert_eq!(
            e.evaluate(ip("89.160.20.128"), None, None).as_deref(),
            Some("10.0.0.2")
        );
        // US client matches nothing
        assert_eq!(e.evaluate(ip("216.160.83.56"), None, None), None);
        // matching is case-insensitive, a bare city name works, other cities do not match
        let e = city_engine(
            city_db().unwrap(),
            vec![
                rule("c", "city", "london", "10.0.0.9", 0, true),
                rule("r", "region", "us-wa", "10.0.0.8", 0, true),
            ],
        );
        assert_eq!(
            e.evaluate(ip("81.2.69.142"), None, None).as_deref(),
            Some("10.0.0.9")
        );
        assert_eq!(
            e.evaluate(ip("216.160.83.56"), None, None).as_deref(),
            Some("10.0.0.8")
        );
        assert_eq!(e.evaluate(ip("89.160.20.128"), None, None), None);
        // disabled rules never match
        let e = city_engine(
            city_db().unwrap(),
            vec![rule("c", "city", "GB:London", "10.0.0.9", 0, false)],
        );
        assert_eq!(e.evaluate(ip("81.2.69.142"), None, None), None);
    }

    #[test]
    fn city_database_handles_ipv6_and_mapped_addresses() {
        let Some(db) = city_db() else { return };
        // the MaxMind test data carries IPv6 networks, e.g. 2001:218::/32 (Japan)
        assert_eq!(db.country(ip("2001:218::1")).as_deref(), Some("JP"));
        // IPv4 mapped into IPv6 resolves like the IPv4 address
        assert_eq!(
            db.city(ip("::ffff:81.2.69.142")).as_deref(),
            Some("GB:London")
        );
    }
}

#[cfg(test)]
mod classify_tests {
    use super::*;
    #[test]
    fn reserved_ranges_are_never_located() {
        for ip in [
            "10.1.2.3",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "192.0.2.5",
            "198.51.100.9",
            "203.0.113.7",
            "198.19.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "::1",
            "fe80::1",
            "fd00::1",
            "2001:db8::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(is_reserved(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8", "81.2.69.142", "2001:4860:4860::8888"] {
            assert!(!is_reserved(ip.parse().unwrap()), "{ip}");
        }
    }
}
