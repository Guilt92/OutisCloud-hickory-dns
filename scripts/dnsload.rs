// Minimal DNS/UDP load generator (std only). Build:  rustc -O -o dnsload scripts/dnsload.rs
// Usage: dnsload -s 127.0.0.1:5353 -d 10 -t 4 -w 64 -q www.example.com:A,mail.example.com:MX [-r 50000]
//   -s server  -d seconds  -t threads  -w in-flight window per thread  -q name:TYPE list
//   -r total target queries/second across all threads (0 = as fast as responses allow)
// Reports achieved qps, response codes, timeouts and latency percentiles.
use std::net::UdpSocket;
use std::time::{Duration, Instant};

fn qtype(s: &str) -> u16 {
    match s.to_ascii_uppercase().as_str() { "A" => 1, "NS" => 2, "CNAME" => 5, "SOA" => 6, "MX" => 15, "TXT" => 16, "AAAA" => 28, "SRV" => 33, "DNSKEY" => 48, "DS" => 43, "RRSIG" => 46, _ => 1 }
}
fn build(id: u16, name: &str, t: u16, dnssec: bool) -> Vec<u8> {
    let mut p = vec![(id >> 8) as u8, id as u8, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, if dnssec { 1 } else { 0 }];
    for l in name.trim_end_matches('.').split('.') { p.push(l.len() as u8); p.extend(l.bytes()); }
    p.push(0); p.extend([(t >> 8) as u8, t as u8, 0, 1]);
    if dnssec { p.extend([0, 0, 41, 0x10, 0, 0, 0, 0x80, 0, 0, 0]); } // EDNS0, 4096 payload, DO bit
    p
}
#[derive(Default, Clone)]
struct Stats { sent: u64, ok: u64, rcodes: [u64; 16], timeouts: u64, lat_us: Vec<u32> }

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let get = |f: &str, d: &str| a.iter().position(|x| x == f).and_then(|i| a.get(i + 1)).cloned().unwrap_or(d.to_string());
    let server = get("-s", "127.0.0.1:53"); let secs: u64 = get("-d", "10").parse().unwrap();
    let threads: usize = get("-t", "4").parse().unwrap(); let window: usize = get("-w", "64").parse().unwrap();
    let rate: u64 = get("-r", "0").parse().unwrap(); let dnssec = a.iter().any(|x| x == "--dnssec");
    let queries: Vec<(String, u16)> = get("-q", "www.example.com:A").split(',').map(|s| { let (n, t) = s.split_once(':').unwrap_or((s, "A")); (n.to_string(), qtype(t)) }).collect();
    let end = Instant::now() + Duration::from_secs(secs);
    let handles: Vec<_> = (0..threads).map(|ti| {
        let (server, queries) = (server.clone(), queries.clone());
        std::thread::spawn(move || {
            let s = UdpSocket::bind("0.0.0.0:0").unwrap(); s.connect(&server).unwrap();
            s.set_read_timeout(Some(Duration::from_millis(1000))).unwrap();
            let mut st = Stats::default(); let mut inflight: Vec<Option<Instant>> = vec![None; 65536];
            let mut next_id: u16 = (ti as u16).wrapping_mul(7919); let mut buf = [0u8; 4096];
            let per_thread = if rate > 0 { rate as f64 / threads as f64 } else { 0.0 };
            let t0 = Instant::now(); let mut out = 0usize; let mut qi = ti;
            while Instant::now() < end {
                // refill window (paced when -r is set)
                while out < window {
                    if per_thread > 0.0 && (st.sent as f64) > per_thread * t0.elapsed().as_secs_f64() { break; }
                    let (n, t) = &queries[qi % queries.len()]; qi += 1;
                    let id = next_id; next_id = next_id.wrapping_add(1);
                    if s.send(&build(id, n, *t, dnssec)).is_ok() { inflight[id as usize] = Some(Instant::now()); out += 1; st.sent += 1; } else { break; }
                }
                match s.recv(&mut buf) {
                    Ok(n) if n >= 12 => {
                        let id = ((buf[0] as usize) << 8) | buf[1] as usize;
                        if let Some(t) = inflight[id].take() { out -= 1; st.ok += 1; st.rcodes[(buf[3] & 0xf) as usize] += 1; st.lat_us.push(t.elapsed().as_micros().min(u32::MAX as u128) as u32); }
                    }
                    Ok(_) => {}
                    Err(_) => { // timeout: everything in flight older than 1s is lost
                        let now = Instant::now();
                        for slot in inflight.iter_mut() { if let Some(t) = slot { if now.duration_since(*t) > Duration::from_millis(1000) { *slot = None; out = out.saturating_sub(1); st.timeouts += 1; } } }
                        if per_thread > 0.0 { std::thread::sleep(Duration::from_micros(200)); }
                    }
                }
            }
            // drain
            let drain_end = Instant::now() + Duration::from_millis(1200);
            while out > 0 && Instant::now() < drain_end {
                if let Ok(n) = s.recv(&mut buf) { if n >= 12 { let id = ((buf[0] as usize) << 8) | buf[1] as usize; if let Some(t) = inflight[id].take() { out -= 1; st.ok += 1; st.rcodes[(buf[3] & 0xf) as usize] += 1; st.lat_us.push(t.elapsed().as_micros() as u32); } } } else { break; }
            }
            st.timeouts += out as u64; st
        })
    }).collect();
    let mut tot = Stats::default();
    for h in handles { let s = h.join().unwrap(); tot.sent += s.sent; tot.ok += s.ok; tot.timeouts += s.timeouts; for i in 0..16 { tot.rcodes[i] += s.rcodes[i]; } tot.lat_us.extend(s.lat_us); }
    tot.lat_us.sort_unstable();
    let pct = |p: f64| if tot.lat_us.is_empty() { 0 } else { tot.lat_us[((tot.lat_us.len() as f64 - 1.0) * p) as usize] };
    println!("sent={} answered={} lost={} ({:.3}% loss)  qps={:.0}", tot.sent, tot.ok, tot.sent.saturating_sub(tot.ok), 100.0 * tot.sent.saturating_sub(tot.ok) as f64 / tot.sent.max(1) as f64, tot.ok as f64 / secs as f64);
    println!("rcodes: NOERROR={} FORMERR={} SERVFAIL={} NXDOMAIN={} NOTIMP={} REFUSED={}", tot.rcodes[0], tot.rcodes[1], tot.rcodes[2], tot.rcodes[3], tot.rcodes[4], tot.rcodes[5]);
    println!("latency us: p50={} p90={} p99={} p99.9={} max={}", pct(0.5), pct(0.9), pct(0.99), pct(0.999), tot.lat_us.last().copied().unwrap_or(0));
}
