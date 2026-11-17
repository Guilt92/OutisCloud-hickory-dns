use std::collections::HashSet;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use crate::proto::rr::rdata::opt::{EdnsCode, EdnsOption};
use crate::proto::rr::{LowerName, Name, RData, RecordSet, RecordType, TSigResponseContext};
use crate::server::RequestInfo;
use crate::zone_handler::{
    AuthLookup, AxfrPolicy, LookupControlFlow, LookupOptions, ZoneHandler, ZoneType,
};

/// Zone handler that applies GeoDNS rules before falling through to other handlers.
///
/// The engine evaluates client IP and optional query context to determine a target
/// string.  Targets must be numeric IP addresses (A/AAAA).
pub struct GeoZoneHandler {
    origin: LowerName,
    engine: geodns::GeoRuleEngine,
    /// owner names that carry an A or AAAA record in the zone file; zone-wide
    /// rules only answer for these (`None`: unknown, old behaviour)
    known_names: Option<HashSet<LowerName>>,
    /// use the EDNS Client Subnet (when a query carries one) instead of the
    /// resolver's address
    ecs: bool,
}

impl GeoZoneHandler {
    pub fn new(origin: Name, engine: geodns::GeoRuleEngine) -> Self {
        Self {
            origin: origin.into(),
            engine,
            known_names: None,
            ecs: false,
        }
    }

    /// Enable EDNS Client Subnet based decisions.
    pub fn with_ecs(mut self, ecs: bool) -> Self {
        self.ecs = ecs;
        self
    }

    /// Learn which names exist from the zone file, so zone-wide rules never
    /// answer for names the zone does not contain. Failure to read the file
    /// leaves the handler in its previous (answer-everything) mode.
    pub fn with_zone_file(mut self, path: &Path) -> Self {
        let origin: Name = self.origin.clone().into();
        match std::fs::read_to_string(path) {
            Ok(text) => match crate::proto::serialize::txt::Parser::new(
                text,
                Some(path.to_owned()),
                Some(origin),
            )
            .parse()
            {
                Ok((_, records)) => {
                    let names = records
                        .iter()
                        .filter(|(k, _)| matches!(k.record_type, RecordType::A | RecordType::AAAA))
                        .map(|(k, _)| k.name.clone())
                        .collect();
                    self.known_names = Some(names);
                }
                Err(e) => tracing::warn!("geodns: cannot parse {}: {e}", path.display()),
            },
            Err(e) => tracing::warn!("geodns: cannot read {}: {e}", path.display()),
        }
        self
    }

    fn lookup_for_ip(
        &self,
        client_ip: IpAddr,
        name: &LowerName,
        rtype: RecordType,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        // only attempt geo routing for A/AAAA queries
        if !(rtype == RecordType::A || rtype == RecordType::AAAA) {
            return LookupControlFlow::Skip;
        }
        let name_str = name.to_string();
        let origin_str = self.origin.to_string();
        let type_str = if rtype == RecordType::A { "A" } else { "AAAA" };
        let exists = self.known_names.as_ref().map_or(true, |k| k.contains(name));

        // Rule `record_name`s are stored relative to the zone (`www`, `@`);
        // resolve them against the zone apex before comparing with the
        // fully-qualified query name.
        if let Some(target) = self.engine.evaluate_in_zone_checked(
            client_ip,
            &name_str,
            type_str,
            &origin_str,
            exists,
        ) {
            // Only IP targets are supported; anything else falls through to the zone data.
            if let Ok(addr) = target.parse::<IpAddr>() {
                // The target's address family must match the question: an
                // IPv4 target can only answer A and an IPv6 target only AAAA.
                let rdata = match (addr, rtype) {
                    (IpAddr::V4(v4), RecordType::A) => RData::A(v4.into()),
                    (IpAddr::V6(v6), RecordType::AAAA) => RData::AAAA(v6.into()),
                    _ => return LookupControlFlow::Skip,
                };
                let mut rrset = RecordSet::with_ttl(Name::from(name.clone()), rtype, 300);
                rrset.add_rdata(rdata);
                let arc = Arc::new(rrset);
                let lookup =
                    crate::zone_handler::auth_lookup::LookupRecords::new(lookup_options, arc);
                return LookupControlFlow::Break(Ok(AuthLookup::from(lookup)));
            }
        }
        LookupControlFlow::Skip
    }
}

#[async_trait::async_trait]
impl ZoneHandler for GeoZoneHandler {
    fn zone_type(&self) -> ZoneType {
        ZoneType::Primary
    }

    fn axfr_policy(&self) -> AxfrPolicy {
        AxfrPolicy::Deny
    }

    fn origin(&self) -> &LowerName {
        &self.origin
    }

    fn uses_client_subnet(&self) -> bool {
        self.ecs
    }

    async fn search(
        &self,
        request: &crate::server::Request,
        lookup_options: LookupOptions,
    ) -> (LookupControlFlow<AuthLookup>, Option<TSigResponseContext>) {
        // This is the entry point the catalog uses for every query.
        let request_info = match request.request_info() {
            Ok(info) => info,
            Err(_) => return (LookupControlFlow::Skip, None),
        };
        let mut client_ip = request_info.src.ip();
        if self.ecs {
            // A usable ECS option (non-zero source prefix) describes the real
            // client; the catalog echoes it back with the scope we used.
            if let Some(EdnsOption::Subnet(cs)) =
                request.edns().and_then(|e| e.option(EdnsCode::Subnet))
            {
                if cs.source_prefix() > 0 {
                    client_ip = cs.addr();
                }
            }
        }
        let name = request_info.query.name();
        let rtype = request_info.query.query_type();
        (
            self.lookup_for_ip(client_ip, name, rtype, lookup_options),
            None,
        )
    }

    async fn nsec_records(
        &self,
        _name: &LowerName,
        _lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        LookupControlFlow::Skip
    }

    #[cfg(feature = "__dnssec")]
    async fn nsec3_records(
        &self,
        _info: crate::zone_handler::Nsec3QueryInfo<'_>,
        _lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        LookupControlFlow::Skip
    }

    /// The geo handler only synthesises answers; denial-of-existence proofs
    /// (and signatures) come from the signed zone handler behind it.
    #[cfg(feature = "__dnssec")]
    fn nx_proof_kind(&self) -> Option<&crate::dnssec::NxProofKind> {
        None
    }

    #[cfg(feature = "metrics")]
    fn metrics_label(&self) -> &'static str {
        "geodns"
    }

    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        request_info: Option<&RequestInfo<'_>>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        match request_info {
            Some(info) => self.lookup_for_ip(info.src.ip(), name, rtype, lookup_options),
            None => LookupControlFlow::Skip,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::xfer::Protocol;
    use crate::proto::op::{Header, LowerQuery, MessageType, OpCode, Query};
    use crate::proto::rr::LowerName;
    use crate::server::RequestInfo;
    use std::net::SocketAddr;
    use std::str::FromStr;

    fn run<T>(f: impl std::future::Future<Output = T>) -> T {
        futures_executor::block_on(f)
    }

    fn rule(
        kind: &str,
        value: &str,
        target: &str,
        name: Option<&str>,
        rtype: Option<&str>,
    ) -> geodns::GeoRule {
        geodns::GeoRule {
            id: "r".into(),
            match_type: kind.into(),
            match_value: value.into(),
            target: target.into(),
            priority: 0,
            enabled: true,
            record_name: name.map(str::to_string),
            record_type: rtype.map(str::to_string),
        }
    }

    fn lookup_with(
        db: Option<geodns::GeoDB>,
        rules: Vec<geodns::GeoRule>,
        client: &str,
        qname: &str,
        qtype: RecordType,
    ) -> LookupControlFlow<AuthLookup> {
        let mut engine = geodns::GeoRuleEngine::new(db);
        engine.set_rules(rules);
        let handler = GeoZoneHandler::new(Name::from_str("example.com.").unwrap(), engine);
        let header = Header::new(0, MessageType::Query, OpCode::Query);
        let query = LowerQuery::from(Query::query(Name::from_str(qname).unwrap(), qtype));
        let info = RequestInfo::new(
            SocketAddr::new(client.parse().unwrap(), 12345),
            Protocol::Udp,
            &header,
            &query,
        );
        let name = LowerName::new(&Name::from_str(qname).unwrap());
        run(handler.lookup(&name, qtype, Some(&info), LookupOptions::default()))
    }

    fn lookup_for(
        r: geodns::GeoRule,
        qname: &str,
        qtype: RecordType,
    ) -> LookupControlFlow<AuthLookup> {
        lookup_with(None, vec![r], "10.0.0.1", qname, qtype)
    }

    fn answer_rdata(flow: LookupControlFlow<AuthLookup>) -> Vec<RData> {
        match flow {
            LookupControlFlow::Break(Ok(AuthLookup::Records { answers, .. })) => {
                answers.iter().map(|r| r.data().clone()).collect()
            }
            LookupControlFlow::Break(Ok(_)) => panic!("expected an answer section"),
            LookupControlFlow::Break(Err(e)) => panic!("lookup error: {e}"),
            LookupControlFlow::Continue(_) => panic!("unexpected Continue"),
            LookupControlFlow::Skip => panic!("expected an answer, handler skipped"),
        }
    }

    #[test]
    fn non_address_queries_fall_through() {
        let r = rule("default", "", "192.0.2.1", None, None);
        assert!(matches!(
            lookup_for(r, "www.example.com.", RecordType::NS),
            LookupControlFlow::Skip
        ));
    }

    #[test]
    fn country_rule_without_database_does_not_match() {
        let r = rule("country", "US", "192.0.2.1", None, None);
        assert!(matches!(
            lookup_for(r, "www.example.com.", RecordType::A),
            LookupControlFlow::Skip
        ));
    }

    #[test]
    fn default_rule_answers_with_the_target() {
        let flow = lookup_for(
            rule("default", "", "5.6.7.8", None, None),
            "www.example.com.",
            RecordType::A,
        );
        assert_eq!(
            answer_rdata(flow),
            vec![RData::A(
                "5.6.7.8".parse::<std::net::Ipv4Addr>().unwrap().into()
            )]
        );
    }

    #[test]
    fn real_geoip_data_selects_the_target_per_client() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../deploy/dns/GeoLite2-Country.mmdb"
        );
        let db = || {
            geodns::GeoDB::open_from_bytes(std::fs::read(path).expect("GeoLite2 dataset")).unwrap()
        };
        let rules = || {
            vec![
                rule("country", "US", "192.0.2.77", None, None),
                rule("continent", "EU", "192.0.2.88", None, None),
            ]
        };
        let a = |client: &str| match lookup_with(
            Some(db()),
            rules(),
            client,
            "www.example.com.",
            RecordType::A,
        ) {
            LookupControlFlow::Skip => None,
            f => Some(answer_rdata(f)),
        };
        assert_eq!(
            a("8.8.8.8").unwrap(),
            vec![RData::A(
                "192.0.2.77".parse::<std::net::Ipv4Addr>().unwrap().into()
            )]
        );
        assert_eq!(
            a("5.9.0.1").unwrap(),
            vec![RData::A(
                "192.0.2.88".parse::<std::net::Ipv4Addr>().unwrap().into()
            )]
        );
        assert_eq!(
            a("2001:4860:4860::8888").unwrap(),
            vec![RData::A(
                "192.0.2.77".parse::<std::net::Ipv4Addr>().unwrap().into()
            )]
        );
        assert!(
            a("41.0.0.1").is_none(),
            "unmatched client falls through to the zone data"
        );
        assert!(a("10.1.2.3").is_none(), "private client has no location");
    }

    #[test]
    fn relative_record_name_matches_fully_qualified_query() {
        // rules are stored as "www" / "@"; the query name is always fully qualified
        let hit = |n: Option<&str>, t: Option<&str>, q: &str| {
            matches!(
                lookup_for(rule("default", "", "192.0.2.1", n, t), q, RecordType::A),
                LookupControlFlow::Break(Ok(_))
            )
        };
        assert!(hit(Some("www"), None, "www.example.com."));
        assert!(!hit(Some("www"), None, "mail.example.com."));
        assert!(hit(Some("@"), None, "example.com."));
        assert!(hit(Some("WWW"), Some("a"), "Www.Example.Com."));
    }

    #[test]
    fn answer_family_must_match_question() {
        // an IPv4 target must never be returned inside an AAAA RRset (or vice versa)
        assert!(matches!(
            lookup_for(
                rule("default", "", "192.0.2.1", None, None),
                "www.example.com.",
                RecordType::AAAA
            ),
            LookupControlFlow::Skip
        ));
        assert!(matches!(
            lookup_for(
                rule("default", "", "2001:db8::1", None, None),
                "www.example.com.",
                RecordType::A
            ),
            LookupControlFlow::Skip
        ));
        let v6 = answer_rdata(lookup_for(
            rule("default", "", "2001:db8::1", None, None),
            "www.example.com.",
            RecordType::AAAA,
        ));
        assert!(matches!(v6[0], RData::AAAA(_)));
    }
}
