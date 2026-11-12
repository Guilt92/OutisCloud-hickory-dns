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
pub const SUPPORTED_TYPES: [&str; 12] = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "SRV", "PTR", "DNSKEY", "DS", "CAA"];

pub fn parse_type(s: &str) -> Option<RecordType> {
    let up = s.trim().to_ascii_uppercase();
    if !SUPPORTED_TYPES.contains(&up.as_str()) { return None; }
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
    pub resolver: String,
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
    if d.is_empty() { return Err("domain is required".into()); }
    if d.len() > 253 { return Err("name too long".into()); }
    if let Ok(ip) = d.parse::<IpAddr>() {
        if rtype != RecordType::PTR { return Err("an IP address can only be used for PTR lookups".into()); }
        let s = match ip {
            IpAddr::V4(v4) => { let o = v4.octets(); format!("{}.{}.{}.{}.in-addr.arpa.", o[3], o[2], o[1], o[0]) }
            IpAddr::V6(v6) => {
                let hex: String = v6.octets().iter().map(|b| format!("{:02x}", b)).collect();
                format!("{}.ip6.arpa.", hex.chars().rev().map(|c| c.to_string()).collect::<Vec<_>>().join("."))
            }
        };
        return Name::from_ascii(&s).map_err(|e| e.to_string());
    }
    if !d.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '*')) {
        return Err("name contains invalid characters".into());
    }
    if d.split('.').any(|l| l.is_empty() || l.len() > 63) { return Err("invalid label length".into()); }
    Name::from_ascii(format!("{}.", d)).map_err(|e| e.to_string())
}

fn records_of<'a>(it: impl Iterator<Item = &'a hickory_proto::rr::Record>) -> Vec<LookupRecord> {
    it.map(|r| LookupRecord {
        name: r.name().to_string(),
        rtype: r.record_type().to_string(),
        ttl: r.ttl(),
        value: match r.data() {
            // keep TXT readable: join the character-strings of one record
            RData::TXT(t) => t.txt_data().iter().map(|b| String::from_utf8_lossy(b).to_string()).collect::<Vec<_>>().join(""),
            other => other.to_string(),
        },
    }).collect()
}

async fn exchange_udp(resolver: SocketAddr, wire: &[u8]) -> Result<Vec<u8>, String> {
    let bind: SocketAddr = if resolver.is_ipv4() { "0.0.0.0:0".parse().unwrap() } else { "[::]:0".parse().unwrap() };
    let sock = tokio::net::UdpSocket::bind(bind).await.map_err(|e| e.to_string())?;
    sock.send_to(wire, resolver).await.map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; 8192];
    loop {
        let (n, from) = tokio::time::timeout(Duration::from_secs(4), sock.recv_from(&mut buf)).await
            .map_err(|_| "resolver timed out".to_string())?.map_err(|e| e.to_string())?;
        if from == resolver { buf.truncate(n); return Ok(buf); }
        // datagrams from other sources are ignored (off-path spoofing)
    }
}

async fn exchange_tcp(resolver: SocketAddr, wire: &[u8]) -> Result<Vec<u8>, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::time::timeout(Duration::from_secs(4), tokio::net::TcpStream::connect(resolver)).await
        .map_err(|_| "resolver timed out".to_string())?.map_err(|e| e.to_string())?;
    let mut framed = (wire.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(wire);
    s.write_all(&framed).await.map_err(|e| e.to_string())?;
    let mut len = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut len)).await
        .map_err(|_| "resolver timed out".to_string())?.map_err(|e| e.to_string())?;
    let mut out = vec![0u8; u16::from_be_bytes(len) as usize];
    tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut out)).await
        .map_err(|_| "resolver timed out".to_string())?.map_err(|e| e.to_string())?;
    Ok(out)
}

/// Ask `resolver` for `rtype` records of `domain`.
pub async fn lookup(resolver: SocketAddr, domain: &str, rtype: RecordType) -> Result<LookupResult, String> {
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
    let mut raw = exchange_udp(resolver, &wire).await?;
    let mut resp = Message::from_vec(&raw).map_err(|e| format!("invalid response: {}", e))?;
    if resp.id() != msg.id() { return Err("mismatched transaction id".into()); }
    if resp.truncated() {
        truncated_udp = true;
        transport = "tcp";
        raw = exchange_tcp(resolver, &wire).await?;
        resp = Message::from_vec(&raw).map_err(|e| format!("invalid response: {}", e))?;
        if resp.id() != msg.id() { return Err("mismatched transaction id".into()); }
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
    let answers: Vec<_> = resp.answers().iter().filter(|r| r.record_type() == rtype || r.record_type() == RecordType::CNAME).collect();
    let records = records_of(answers.into_iter());
    let authority = records_of(resp.authorities().iter().filter(|r| r.record_type() == RecordType::SOA));
    let note = if status == "NXDOMAIN" {
        Some("The name does not exist (NXDOMAIN).".to_string())
    } else if status != "NOERROR" {
        Some(format!("The resolver answered {}.", status))
    } else if !records.iter().any(|r| r.rtype == rtype.to_string()) {
        Some(format!("The name exists but has no {} records (NOERROR/NODATA).", rtype))
    } else { None };
    Ok(LookupResult {
        domain: domain.trim().trim_end_matches('.').to_string(),
        record_type: rtype.to_string(),
        status,
        authoritative: resp.authoritative(),
        truncated_udp,
        recursion_available: resp.recursion_available(),
        resolver: resolver.to_string(),
        transport: transport.to_string(),
        elapsed_ms: started.elapsed().as_millis(),
        records,
        authority,
        note,
    })
}

// ---------------------------------------------------------------------------
// Per-user rate limit (fixed window). Lookups go to a shared resolver, so one account must not be
// able to turn the tool into a query flood.
// ---------------------------------------------------------------------------

static WINDOWS: once_cell::sync::Lazy<std::sync::Mutex<std::collections::HashMap<String, (Instant, u32)>>> =
    once_cell::sync::Lazy::new(Default::default);

pub fn rate_limit_per_minute() -> u32 {
    std::env::var("DNS_LOOKUP_RATE_PER_MIN").ok().and_then(|v| v.parse().ok()).unwrap_or(30)
}

/// `Ok(())` if the caller may query now, otherwise the number of seconds to wait.
pub fn check_rate(key: &str, limit: u32) -> Result<(), u64> {
    let mut w = WINDOWS.lock().unwrap();
    let now = Instant::now();
    if w.len() > 10_000 { w.retain(|_, (t, _)| now.duration_since(*t) < Duration::from_secs(60)); }
    let e = w.entry(key.to_string()).or_insert((now, 0));
    if now.duration_since(e.0) >= Duration::from_secs(60) { *e = (now, 0); }
    if e.1 >= limit { return Err(60 - now.duration_since(e.0).as_secs().min(59)); }
    e.1 += 1;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reverse_names() {
        assert_eq!(query_name("192.0.2.10", RecordType::PTR).unwrap().to_string(), "10.2.0.192.in-addr.arpa.");
        assert!(query_name("2001:db8::1", RecordType::PTR).unwrap().to_string().ends_with("8.b.d.0.1.0.0.2.ip6.arpa."));
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
        for t in SUPPORTED_TYPES { assert!(parse_type(t).is_some(), "{}", t); }
        assert!(parse_type("ANY").is_none());
        assert!(parse_type("AXFR").is_none());
    }
    #[test]
    fn window_limits() {
        let k = format!("k{}", rand::random::<u64>());
        for _ in 0..3 { assert!(check_rate(&k, 3).is_ok()); }
        assert!(check_rate(&k, 3).is_err());
    }
}
