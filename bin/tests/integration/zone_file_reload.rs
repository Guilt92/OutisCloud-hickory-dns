//! End-to-end check of zone hot reload: the server watches its zone directory
//! and swaps the in-memory data without restarting. A broken zone file must be
//! rejected while the previous data keeps being served.

use std::io::{BufRead, BufReader};
use std::net::{Ipv4Addr, SocketAddr};
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::time::{Duration, Instant};

use hickory_net::client::{Client, ClientHandle};
use hickory_net::runtime::TokioRuntimeProvider;
use hickory_net::udp::UdpClientStream;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{DNSClass, Name, RData, RecordType, rdata::A};
use regex::Regex;
use tempfile::tempdir;

const ZONE_HEAD: &str = "example.com. 3600 IN SOA ns1.example.com. hostmaster.example.com. {SERIAL} 3600 3600 604800 3600\nexample.com. 3600 IN NS ns1.example.com.\nns1.example.com. 3600 IN A 127.0.0.1\nwww.example.com. 300 IN A 127.0.0.1\n";

fn write_zone(path: &std::path::Path, serial: u32, extra: &str) {
    // atomic replace, exactly like the control API publisher does
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, format!("{}{}", ZONE_HEAD.replace("{SERIAL}", &serial.to_string()), extra)).unwrap();
    std::fs::rename(&tmp, path).unwrap();
}

struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn a_records(client: &mut Client<TokioRuntimeProvider>, name: &str) -> (ResponseCode, Vec<A>) {
    let resp = client
        .query(Name::from_str(name).unwrap(), DNSClass::IN, RecordType::A)
        .await
        .expect("query");
    let answers = resp
        .answers()
        .iter()
        .filter_map(|r| match r.data() {
            RData::A(a) => Some(*a),
            _ => None,
        })
        .collect();
    (resp.response_code(), answers)
}

async fn eventually<F: FnMut() -> Fut, Fut: std::future::Future<Output = bool>>(what: &str, mut f: F) {
    let end = Instant::now() + Duration::from_secs(15);
    while Instant::now() < end {
        if f().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("timed out waiting for: {what}");
}

#[tokio::test]
async fn reload_on_zonefile_change() {
    let tmp = tempdir().unwrap();
    let zonedir = tmp.path().join("zones");
    std::fs::create_dir_all(&zonedir).unwrap();
    let zone_path = zonedir.join("zone.example.com");
    write_zone(&zone_path, 1, "");

    let conf = tmp.path().join("named.toml");
    std::fs::write(
        &conf,
        format!(
            "listen_addrs_ipv4 = [\"127.0.0.1\"]\n\n[[zones]]\nzone = \"example.com\"\nzone_type = \"Primary\"\n\n[[zones.stores]]\ntype = \"file\"\nzone_path = \"{}\"\n",
            zone_path.display()
        ),
    )
    .unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_hickory-dns"))
        .stdout(Stdio::piped())
        .arg("-d")
        .arg(format!("--config={}", conf.display()))
        .arg(format!("--zonedir={}", zonedir.display()))
        .arg("--port=0")
        .spawn()
        .expect("spawn server");
    let pid = child.id();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let server = Server(child);

    let re = Regex::new(r"listening for UDP on (127\.0\.0\.1:\d+)").unwrap();
    let mut addr = None;
    let end = Instant::now() + Duration::from_secs(30);
    while Instant::now() < end {
        let mut line = String::new();
        if stdout.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        if let Some(c) = re.captures(&line) {
            addr = Some(SocketAddr::from_str(&c[1]).unwrap());
        }
        if line.contains("awaiting connections") {
            break;
        }
    }
    let addr = addr.expect("server did not announce its UDP port");
    assert_eq!(addr.ip(), Ipv4Addr::LOCALHOST);
    // keep draining stdout so the server never blocks on a full pipe
    std::thread::spawn(move || {
        let mut l = String::new();
        while stdout.read_line(&mut l).unwrap_or(0) > 0 {
            l.clear();
        }
    });

    let stream = UdpClientStream::builder(addr, TokioRuntimeProvider::new()).build();
    let (mut client, bg) = Client::<TokioRuntimeProvider>::from_sender(stream);
    tokio::spawn(bg);

    let (rc, a) = a_records(&mut client, "www.example.com.").await;
    assert_eq!((rc, a), (ResponseCode::NoError, vec![A::new(127, 0, 0, 1)]));
    assert_eq!(a_records(&mut client, "foo.example.com.").await.0, ResponseCode::NXDomain);

    // add a record: picked up without a restart
    write_zone(&zone_path, 2, "foo.example.com. 300 IN A 5.6.7.8\n");
    let mut c2 = client.clone();
    eventually("new record is served after reload", || {
        let mut c = c2.clone();
        async move { a_records(&mut c, "foo.example.com.").await.1 == vec![A::new(5, 6, 7, 8)] }
    })
    .await;
    // old data stays
    assert_eq!(a_records(&mut c2, "www.example.com.").await.1, vec![A::new(127, 0, 0, 1)]);

    // a broken zone file is rejected; previous data keeps being served
    write_zone(&zone_path, 3, "this is not a valid record line\n");
    tokio::time::sleep(Duration::from_secs(2)).await;
    let (rc, a) = a_records(&mut c2, "foo.example.com.").await;
    assert_eq!((rc, a), (ResponseCode::NoError, vec![A::new(5, 6, 7, 8)]), "bad zone must not replace good data");

    // and a later good file is applied again
    write_zone(&zone_path, 4, "foo.example.com. 300 IN A 9.9.9.9\n");
    eventually("fixed zone is applied", || {
        let mut c = c2.clone();
        async move { a_records(&mut c, "foo.example.com.").await.1 == vec![A::new(9, 9, 9, 9)] }
    })
    .await;

    // the same process served all of it (hot reload, not restart)
    assert_eq!(server.0.id(), pid);
}
