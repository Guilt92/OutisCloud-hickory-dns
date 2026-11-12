//! Real DNS lookups for the dashboard's "DNS Lookup" tool.
//!
//! The query is sent with the wire protocol (UDP with EDNS0, retried over TCP when the answer is
//! truncated) to the configured resolver (`DNS_LOOKUP_RESOLVER`, default `DNS_VERIFY_RESOLVER`).
//! Nothing is invented: the response code, flags, TTLs and records are exactly what the resolver
//! returned, and an empty answer is reported as NOERROR/NODATA or NXDOMAIN.

use hickory_proto::op::{Edns, Message, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use serde::Serialize;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

/// Record types the tool really supports (and the UI offers). Each is covered by tests.
pub const SUPPORTED_TYPES: [&str; 12] = [
    "A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "SRV", "PTR", "DNSKEY", "DS", "CAA",
];

pub fn parse_type(s: &str) -> Option<RecordType> {
    let up = s.trim().to_ascii_uppercase();
    if !SUPPORTED_TYPES.contains(&up.as_str()) {
        return None;
    }
    up.parse().ok()
}

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct LookupRecord {
    pub name: String,
    #[serde(rename = "type")]
    pub rtype: String,
    pub ttl: u32,
    pub value: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct LookupResult {
    pub domain: String,
    pub record_type: String,
    /// NOERROR, NXDOMAIN, SERVFAIL, REFUSED, ...
    pub status: String,
    pub authoritative: bool,
    pub truncated_udp: bool,
    pub recursion_available: bool,
    /// address of the resolver that answered; only exposed to administrators
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolver: Option<String>,
    /// per-resolver outcome of this lookup; administrators only
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub attempts: Vec<Attempt>,
    pub transport: String,
    pub elapsed_ms: u128,
    pub records: Vec<LookupRecord>,
    /// records of the authority section (the SOA that proves NXDOMAIN/NODATA)
    pub authority: Vec<LookupRecord>,
    pub note: Option<String>,
}

/// Normalise the input into a query name. IP addresses become their reverse (`in-addr.arpa` /
/// `ip6.arpa`) name, which is what a PTR lookup needs.
pub fn query_name(input: &str, rtype: RecordType) -> Result<Name, String> {
    let d = input.trim().trim_end_matches('.');
    if d.is_empty() {
        return Err("domain is required".into());
    }
    if d.len() > 253 {
        return Err("name too long".into());
    }
    if let Ok(ip) = d.parse::<IpAddr>() {
        if rtype != RecordType::PTR {
            return Err("an IP address can only be used for PTR lookups".into());
        }
        let s = match ip {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                format!("{}.{}.{}.{}.in-addr.arpa.", o[3], o[2], o[1], o[0])
            }
            IpAddr::V6(v6) => {
                let hex: String = v6.octets().iter().map(|b| format!("{:02x}", b)).collect();
                format!(
                    "{}.ip6.arpa.",
                    hex.chars()
                        .rev()
                        .map(|c| c.to_string())
                        .collect::<Vec<_>>()
                        .join(".")
                )
            }
        };
        return Name::from_ascii(&s).map_err(|e| e.to_string());
    }
    if !d
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '*'))
    {
        return Err("name contains invalid characters".into());
    }
    if d.split('.').any(|l| l.is_empty() || l.len() > 63) {
        return Err("invalid label length".into());
    }
    Name::from_ascii(format!("{}.", d)).map_err(|e| e.to_string())
}

fn records_of<'a>(it: impl Iterator<Item = &'a hickory_proto::rr::Record>) -> Vec<LookupRecord> {
    it.map(|r| LookupRecord {
        name: r.name().to_string(),
        rtype: r.record_type().to_string(),
        ttl: r.ttl(),
        value: match r.data() {
            // keep TXT readable: join the character-strings of one record
            RData::TXT(t) => t
                .txt_data()
                .iter()
                .map(|b| String::from_utf8_lossy(b).to_string())
                .collect::<Vec<_>>()
                .join(""),
            other => other.to_string(),
        },
    })
    .collect()
}

async fn exchange_udp(
    resolver: SocketAddr,
    wire: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    let bind: SocketAddr = if resolver.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let sock = tokio::net::UdpSocket::bind(bind)
        .await
        .map_err(|e| e.to_string())?;
    sock.send_to(wire, resolver)
        .await
        .map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; 8192];
    loop {
        let (n, from) = tokio::time::timeout(timeout, sock.recv_from(&mut buf))
            .await
            .map_err(|_| "resolver timed out".to_string())?
            .map_err(|e| e.to_string())?;
        if from == resolver {
            buf.truncate(n);
            return Ok(buf);
        }
        // datagrams from other sources are ignored (off-path spoofing)
    }
}

async fn exchange_tcp(
    resolver: SocketAddr,
    wire: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(resolver))
        .await
        .map_err(|_| "resolver timed out".to_string())?
        .map_err(|e| e.to_string())?;
    let mut framed = (wire.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(wire);
    s.write_all(&framed).await.map_err(|e| e.to_string())?;
    let mut len = [0u8; 2];
    tokio::time::timeout(timeout, s.read_exact(&mut len))
        .await
        .map_err(|_| "resolver timed out".to_string())?
        .map_err(|e| e.to_string())?;
    let mut out = vec![0u8; u16::from_be_bytes(len) as usize];
    tokio::time::timeout(timeout, s.read_exact(&mut out))
        .await
        .map_err(|_| "resolver timed out".to_string())?
        .map_err(|e| e.to_string())?;
    Ok(out)
}

/// Ask `resolver` for `rtype` records of `domain`.
pub async fn lookup(
    resolver: SocketAddr,
    domain: &str,
    rtype: RecordType,
    timeout: Duration,
) -> Result<LookupResult, String> {
    let name = query_name(domain, rtype)?;
    let mut msg = Message::query();
    msg.set_recursion_desired(true);
    msg.add_query(Query::query(name.clone(), rtype));
    let mut edns = Edns::new();
    edns.set_max_payload(1232);
    msg.set_edns(edns);
    let wire = msg.to_vec().map_err(|e| e.to_string())?;

    let started = Instant::now();
    let mut transport = "udp";
    let mut truncated_udp = false;
    let mut raw = exchange_udp(resolver, &wire, timeout).await?;
    let mut resp = Message::from_vec(&raw).map_err(|e| format!("invalid response: {}", e))?;
    if resp.id() != msg.id() {
        return Err("mismatched transaction id".into());
    }
    if resp.truncated() {
        truncated_udp = true;
        transport = "tcp";
        raw = exchange_tcp(resolver, &wire, timeout).await?;
        resp = Message::from_vec(&raw).map_err(|e| format!("invalid response: {}", e))?;
        if resp.id() != msg.id() {
            return Err("mismatched transaction id".into());
        }
    }
    let status = match resp.response_code() {
        ResponseCode::NoError => "NOERROR".to_string(),
        ResponseCode::NXDomain => "NXDOMAIN".to_string(),
        ResponseCode::ServFail => "SERVFAIL".to_string(),
        ResponseCode::Refused => "REFUSED".to_string(),
        ResponseCode::FormErr => "FORMERR".to_string(),
        other => format!("{}", other).to_ascii_uppercase(),
    };
    // keep only records of the requested type, plus the CNAME chain that led to them
    let answers: Vec<_> = resp
        .answers()
        .iter()
        .filter(|r| r.record_type() == rtype || r.record_type() == RecordType::CNAME)
        .collect();
    let records = records_of(answers.into_iter());
    let authority = records_of(
        resp.authorities()
            .iter()
            .filter(|r| r.record_type() == RecordType::SOA),
    );
    let note = if status == "NXDOMAIN" {
        Some("The name does not exist (NXDOMAIN).".to_string())
    } else if status != "NOERROR" {
        Some(format!("The resolver answered {}.", status))
    } else if !records.iter().any(|r| r.rtype == rtype.to_string()) {
        Some(format!(
            "The name exists but has no {} records (NOERROR/NODATA).",
            rtype
        ))
    } else {
        None
    };
    Ok(LookupResult {
        domain: domain.trim().trim_end_matches('.').to_string(),
        record_type: rtype.to_string(),
        status,
        authoritative: resp.authoritative(),
        truncated_udp,
        recursion_available: resp.recursion_available(),
        resolver: Some(resolver.to_string()),
        attempts: vec![],
        transport: transport.to_string(),
        elapsed_ms: started.elapsed().as_millis(),
        records,
        authority,
        note,
    })
}

// ---------------------------------------------------------------------------
// Resolver set: ordered failover, optional admin-only selection by label
// ---------------------------------------------------------------------------

/// One configured resolver. `DNS_LOOKUP_RESOLVERS="internal=10.0.0.53,[2001:db8::53]:53,192.0.2.1:5353"`:
/// comma separated, optional `label=` prefix, IPv4 `a.b.c.d[:port]`, IPv6 `[addr]:port` or bare `addr`; default port 53.
#[derive(Clone, Debug, PartialEq)]
pub struct ResolverSpec {
    pub label: String,
    pub addr: SocketAddr,
}

pub const MAX_RESOLVERS: usize = 8;

pub fn parse_resolvers(spec: &str) -> Result<Vec<ResolverSpec>, String> {
    let mut out: Vec<ResolverSpec> = vec![];
    for (i, raw) in spec
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .enumerate()
    {
        let (label, addr) = match raw.split_once('=') {
            Some((l, a)) => (l.trim().to_string(), a.trim()),
            None => (format!("resolver{}", i + 1), raw),
        };
        if label.is_empty()
            || !label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            || label.len() > 32
        {
            return Err(format!("invalid resolver label in '{}'", raw));
        }
        let sock: SocketAddr = if let Ok(s) = addr.parse::<SocketAddr>() {
            s
        } else if let Ok(ip) = addr.parse::<IpAddr>() {
            SocketAddr::new(ip, 53)
        } else {
            return Err(format!(
                "invalid resolver address '{}' (expected ip, ip:port or [ipv6]:port)",
                addr
            ));
        };
        if sock.port() == 0 {
            return Err(format!("invalid port in '{}'", addr));
        }
        if sock.ip().is_unspecified() || sock.ip().is_multicast() {
            return Err(format!("resolver address '{}' is not usable", addr));
        }
        if out.iter().any(|r| r.label == label) {
            return Err(format!("duplicate resolver label '{}'", label));
        }
        out.push(ResolverSpec { label, addr: sock });
    }
    if out.len() > MAX_RESOLVERS {
        return Err(format!("at most {} resolvers are supported", MAX_RESOLVERS));
    }
    Ok(out)
}

/// Where the resolver list comes from, in order: `DNS_LOOKUP_RESOLVERS`, an explicitly set `DNS_VERIFY_RESOLVER`,
/// the host's `/etc/resolv.conf`. There is deliberately NO built-in public resolver: with nothing configured the
/// tool reports "not configured" instead of silently sending customers' queries to a third party.
pub fn resolvers_from_env() -> Result<Vec<ResolverSpec>, String> {
    if let Ok(v) = std::env::var("DNS_LOOKUP_RESOLVERS") {
        if !v.trim().is_empty() {
            return parse_resolvers(&v).map_err(|e| format!("DNS_LOOKUP_RESOLVERS: {}", e));
        }
    }
    if let Ok(v) = std::env::var("DNS_VERIFY_RESOLVER") {
        if !v.trim().is_empty() {
            return parse_resolvers(&v).map_err(|e| format!("DNS_VERIFY_RESOLVER: {}", e));
        }
    }
    if let Ok(text) = std::fs::read_to_string("/etc/resolv.conf") {
        let list: Vec<String> = text
            .lines()
            .filter_map(|l| {
                l.trim()
                    .strip_prefix("nameserver ")
                    .map(|s| s.trim().to_string())
            })
            .collect();
        if let Ok(v) = parse_resolvers(&list.join(",")) {
            return Ok(v);
        }
    }
    Ok(vec![])
}

pub fn timeout_per_resolver() -> Duration {
    Duration::from_millis(
        std::env::var("DNS_LOOKUP_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(2000)
            .clamp(100, 10_000),
    )
}
pub fn total_deadline() -> Duration {
    Duration::from_millis(
        std::env::var("DNS_LOOKUP_DEADLINE_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(6000)
            .clamp(200, 30_000),
    )
}

#[derive(Serialize, Debug, Clone)]
pub struct Attempt {
    pub resolver: String,
    pub address: String,
    pub outcome: String,
}

/// Resolvers that failed recently are tried last (not skipped), so a dead primary costs one timeout, not one per query.
static RECENT_FAIL: once_cell::sync::Lazy<
    std::sync::Mutex<std::collections::HashMap<SocketAddr, Instant>>,
> = once_cell::sync::Lazy::new(Default::default);
const FAIL_MEMORY: Duration = Duration::from_secs(15);

fn ordered(specs: &[ResolverSpec]) -> Vec<ResolverSpec> {
    let now = Instant::now();
    let m = RECENT_FAIL.lock().unwrap();
    let (mut healthy, mut bad): (Vec<_>, Vec<_>) = specs.iter().cloned().partition(|s| {
        m.get(&s.addr)
            .map(|t| now.duration_since(*t) > FAIL_MEMORY)
            .unwrap_or(true)
    });
    healthy.append(&mut bad);
    healthy
}

/// Try the resolvers in order (each at most once; TCP only for truncated answers) within one overall deadline.
/// Definitive answers (NOERROR, NXDOMAIN) stop the search. Network failures, timeouts, SERVFAIL, REFUSED and
/// FORMERR move on to the next resolver; if every resolver answered with such a status the last status is
/// returned as is, and if none answered at all the error carries the per-resolver attempts.
pub async fn lookup_failover(
    specs: &[ResolverSpec],
    only: Option<&str>,
    domain: &str,
    rtype: RecordType,
    per: Duration,
    deadline: Duration,
) -> Result<LookupResult, (String, Vec<Attempt>)> {
    let list: Vec<ResolverSpec> = match only {
        Some(l) => specs.iter().filter(|s| s.label == l).cloned().collect(),
        None => ordered(specs),
    };
    if list.is_empty() {
        return Err(("no such resolver".into(), vec![]));
    }
    let started = Instant::now();
    let mut attempts: Vec<Attempt> = vec![];
    let mut last_status: Option<LookupResult> = None;
    for s in list {
        let left = deadline.saturating_sub(started.elapsed());
        if left < Duration::from_millis(50) {
            attempts.push(Attempt {
                resolver: s.label.clone(),
                address: s.addr.to_string(),
                outcome: "skipped: deadline reached".into(),
            });
            continue;
        }
        match lookup(s.addr, domain, rtype, per.min(left)).await {
            Ok(mut r) => {
                let retry = matches!(r.status.as_str(), "SERVFAIL" | "REFUSED" | "FORMERR");
                attempts.push(Attempt {
                    resolver: s.label.clone(),
                    address: s.addr.to_string(),
                    outcome: r.status.clone(),
                });
                if !retry {
                    RECENT_FAIL.lock().unwrap().remove(&s.addr);
                    r.attempts = attempts;
                    r.resolver = Some(format!("{} ({})", s.label, s.addr));
                    return Ok(r);
                }
                RECENT_FAIL.lock().unwrap().insert(s.addr, Instant::now());
                r.resolver = Some(format!("{} ({})", s.label, s.addr));
                last_status = Some(r);
            }
            Err(e)
                if e.contains("required")
                    || e.contains("invalid")
                    || e.contains("too long")
                    || e.contains("only be used")
                    || e.contains("characters") =>
            {
                return Err((e, attempts)); // a bad question fails identically everywhere
            }
            Err(e) => {
                RECENT_FAIL.lock().unwrap().insert(s.addr, Instant::now());
                attempts.push(Attempt {
                    resolver: s.label.clone(),
                    address: s.addr.to_string(),
                    outcome: e,
                });
            }
        }
    }
    match last_status {
        Some(mut r) => {
            r.attempts = attempts;
            Ok(r)
        }
        None => Err(("all resolvers failed".into(), attempts)),
    }
}

// ---------------------------------------------------------------------------
// Per-user rate limit (fixed window). Lookups go to a shared resolver, so one account must not be
// able to turn the tool into a query flood.
// ---------------------------------------------------------------------------

static WINDOWS: once_cell::sync::Lazy<
    std::sync::Mutex<std::collections::HashMap<String, (Instant, u32)>>,
> = once_cell::sync::Lazy::new(Default::default);

pub fn rate_limit_per_minute() -> u32 {
    std::env::var("DNS_LOOKUP_RATE_PER_MIN")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30)
}

/// `Ok(())` if the caller may query now, otherwise the number of seconds to wait.
pub fn check_rate(key: &str, limit: u32) -> Result<(), u64> {
    let mut w = WINDOWS.lock().unwrap();
    let now = Instant::now();
    if w.len() > 10_000 {
        w.retain(|_, (t, _)| now.duration_since(*t) < Duration::from_secs(60));
    }
    let e = w.entry(key.to_string()).or_insert((now, 0));
    if now.duration_since(e.0) >= Duration::from_secs(60) {
        *e = (now, 0);
    }
    if e.1 >= limit {
        return Err(60 - now.duration_since(e.0).as_secs().min(59));
    }
    e.1 += 1;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reverse_names() {
        assert_eq!(
            query_name("192.0.2.10", RecordType::PTR)
                .unwrap()
                .to_string(),
            "10.2.0.192.in-addr.arpa."
        );
        assert!(
            query_name("2001:db8::1", RecordType::PTR)
                .unwrap()
                .to_string()
                .ends_with("8.b.d.0.1.0.0.2.ip6.arpa.")
        );
        assert!(query_name("192.0.2.10", RecordType::A).is_err());
    }
    #[test]
    fn input_validation() {
        assert!(query_name("", RecordType::A).is_err());
        assert!(query_name("bad name.com", RecordType::A).is_err());
        assert!(query_name("a..b", RecordType::A).is_err());
        assert!(query_name(&"a".repeat(64), RecordType::A).is_err());
        assert!(query_name("_dmarc.example.com", RecordType::TXT).is_ok());
    }
    #[test]
    fn only_supported_types() {
        for t in SUPPORTED_TYPES {
            assert!(parse_type(t).is_some(), "{}", t);
        }
        assert!(parse_type("ANY").is_none());
        assert!(parse_type("AXFR").is_none());
    }
    #[test]
    fn window_limits() {
        let k = format!("k{}", rand::random::<u64>());
        for _ in 0..3 {
            assert!(check_rate(&k, 3).is_ok());
        }
        assert!(check_rate(&k, 3).is_err());
    }
}

#[cfg(test)]
mod resolver_tests {
    use super::*;
    #[test]
    fn parses_v4_v6_labels_and_ports() {
        let v =
            parse_resolvers("internal=10.0.0.53, [2001:db8::53]:5353 ,2001:db8::1,192.0.2.1:5300")
                .unwrap();
        assert_eq!(v.len(), 4);
        assert_eq!(
            v[0],
            ResolverSpec {
                label: "internal".into(),
                addr: "10.0.0.53:53".parse().unwrap()
            }
        );
        assert_eq!(v[1].addr, "[2001:db8::53]:5353".parse().unwrap());
        assert_eq!(v[2].addr, "[2001:db8::1]:53".parse().unwrap());
        assert_eq!(v[3].addr.port(), 5300);
    }
    #[test]
    fn rejects_invalid_configuration() {
        for bad in [
            "nonsense",
            "10.0.0.1:0",
            "0.0.0.0",
            "224.0.0.1",
            "a b=10.0.0.1",
            "x=10.0.0.1,x=10.0.0.2",
            "10.0.0.256",
            "=10.0.0.1",
            "1.1.1.1:99999",
        ] {
            assert!(parse_resolvers(bad).is_err(), "{bad} must be rejected");
        }
        assert!(
            parse_resolvers(
                &(1..=9)
                    .map(|i| format!("10.0.0.{i}"))
                    .collect::<Vec<_>>()
                    .join(",")
            )
            .is_err(),
            "too many"
        );
        assert!(parse_resolvers("").unwrap().is_empty());
    }
}
