//! Minimal std-only HTTP/1.1 load generator for the control API benchmarks (keep-alive connections, latency percentiles).
//! Build: rustc -O scripts/httpload.rs -o httpload
//! Usage: httpload <host:port> <METHOD> <path> [-c conns] [-d seconds] [-H "Name: value"]... [-b 'json body'] [-w warmup_seconds]
//! Prints one JSON line: requests, errors, status histogram, rps, min/p50/p90/p95/p99/max in milliseconds.
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 4 { eprintln!("usage: httpload host:port METHOD path [-c N] [-d SECS] [-w SECS] [-H hdr]... [-b body]"); std::process::exit(2); }
    let (addr, method, path) = (a[1].clone(), a[2].clone(), a[3].clone());
    let (mut conns, mut secs, mut warm, mut hdrs, mut body) = (8usize, 10f64, 1f64, vec![], String::new());
    let mut i = 4;
    while i + 1 < a.len() { match a[i].as_str() { "-c" => conns = a[i + 1].parse().unwrap(), "-d" => secs = a[i + 1].parse().unwrap(), "-w" => warm = a[i + 1].parse().unwrap(), "-H" => hdrs.push(a[i + 1].clone()), "-b" => body = a[i + 1].clone(), _ => {} } i += 2; }
    let mut req = format!("{} {} HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\n", method, path, addr);
    for h in &hdrs { req.push_str(h); req.push_str("\r\n"); }
    if !body.is_empty() { req.push_str(&format!("Content-Type: application/json\r\nContent-Length: {}\r\n", body.len())); }
    req.push_str("\r\n"); req.push_str(&body);
    let req = Arc::new(req.into_bytes());
    let lat: Arc<Mutex<Vec<f64>>> = Arc::new(Mutex::new(vec![]));
    let status: Arc<Mutex<std::collections::BTreeMap<u16, u64>>> = Arc::new(Mutex::new(Default::default()));
    let errors = Arc::new(Mutex::new(0u64));
    let start = Instant::now(); let warm_end = start + Duration::from_secs_f64(warm); let end = warm_end + Duration::from_secs_f64(secs);
    let mut hs = vec![];
    for _ in 0..conns {
        let (addr, req, lat, status, errors) = (addr.clone(), req.clone(), lat.clone(), status.clone(), errors.clone());
        hs.push(std::thread::spawn(move || {
            let mut s = TcpStream::connect(&addr).expect("connect"); s.set_nodelay(true).ok(); s.set_read_timeout(Some(Duration::from_secs(60))).ok();
            let mut local = vec![]; let mut buf = vec![0u8; 1 << 16];
            while Instant::now() < end {
                let t0 = Instant::now();
                if s.write_all(&req).is_err() { *errors.lock().unwrap() += 1; s = match TcpStream::connect(&addr) { Ok(x) => x, Err(_) => break }; continue; }
                // read headers
                let mut data: Vec<u8> = vec![];
                let (hend, code) = loop {
                    let n = match s.read(&mut buf) { Ok(0) | Err(_) => { *errors.lock().unwrap() += 1; 0 }, Ok(n) => { data.extend_from_slice(&buf[..n]); n } };
                    if n == 0 { break (0, 0); }
                    if let Some(p) = data.windows(4).position(|w| w == b"\r\n\r\n") { let c = std::str::from_utf8(&data[9..12]).ok().and_then(|x| x.parse().ok()).unwrap_or(0); break (p + 4, c); }
                };
                if hend == 0 { s = match TcpStream::connect(&addr) { Ok(x) => x, Err(_) => break }; continue; }
                let head = String::from_utf8_lossy(&data[..hend]).to_ascii_lowercase();
                let clen = head.lines().find_map(|l| l.strip_prefix("content-length:").and_then(|v| v.trim().parse::<usize>().ok()));
                let chunked = head.contains("transfer-encoding: chunked");
                if let Some(cl) = clen { while data.len() < hend + cl { match s.read(&mut buf) { Ok(0) | Err(_) => break, Ok(n) => data.extend_from_slice(&buf[..n]) } } }
                else if chunked { while !data.ends_with(b"0\r\n\r\n") { match s.read(&mut buf) { Ok(0) | Err(_) => break, Ok(n) => data.extend_from_slice(&buf[..n]) } } }
                let ms = t0.elapsed().as_secs_f64() * 1000.0;
                if t0 >= warm_end { local.push(ms); *status.lock().unwrap().entry(code).or_insert(0) += 1; }
            }
            lat.lock().unwrap().extend(local);
        }));
    }
    for h in hs { h.join().ok(); }
    let mut l = lat.lock().unwrap().clone(); l.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = l.len(); let p = |q: f64| if n == 0 { 0.0 } else { l[((n as f64 - 1.0) * q).round() as usize] };
    let st = status.lock().unwrap();
    let hist = st.iter().map(|(k, v)| format!("\"{}\":{}", k, v)).collect::<Vec<_>>().join(",");
    println!("{{\"requests\":{},\"errors\":{},\"status\":{{{}}},\"rps\":{:.1},\"min_ms\":{:.2},\"p50_ms\":{:.2},\"p90_ms\":{:.2},\"p95_ms\":{:.2},\"p99_ms\":{:.2},\"max_ms\":{:.2},\"conns\":{}}}",
        n, *errors.lock().unwrap(), hist, n as f64 / secs, l.first().copied().unwrap_or(0.0), p(0.50), p(0.90), p(0.95), p(0.99), l.last().copied().unwrap_or(0.0), conns);
}
