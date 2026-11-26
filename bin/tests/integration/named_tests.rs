// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#[cfg(feature = "sqlite")]
use futures_util::StreamExt;
use std::io::{Read, Write};
use std::net::*;
use std::process::{Command, Stdio};
use std::str::FromStr;
use std::time::Duration;

#[cfg(feature = "metrics")]
use crate::server_harness::ServerProtocol;
use crate::server_harness::{TestServer, query_a, query_a_refused, query_message};
use hickory_net::client::{Client, ClientHandle};
#[cfg(feature = "__h3")]
use hickory_net::h3::H3ClientStream;
use hickory_net::runtime::TokioRuntimeProvider;
use hickory_net::tcp::TcpClientStream;
use hickory_net::udp::UdpClientStream;
#[cfg(feature = "__dnssec")]
use hickory_net::xfer::DnsMultiplexer;
use hickory_net::xfer::Protocol;
#[cfg(feature = "__h3")]
use hickory_net::xfer::{DnsRequestSender, FirstAnswer};
use hickory_proto::op::ResponseCode;
#[cfg(feature = "__h3")]
use hickory_proto::op::{DnsRequest, DnsRequestOptions, Message, Query};
use hickory_proto::rr::RData;
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{DNSClass, Name, RecordType};
#[cfg(feature = "__dnssec")]
use hickory_proto::rr::{TSigner, rdata::tsig::TsigAlgorithm};
#[cfg(feature = "__h3")]
use std::sync::Arc;
use test_support::subscribe;

#[tokio::test]
#[cfg(all(feature = "__h3", feature = "sqlite"))]
async fn doh3_client_queries_local_authoritative_server() {
    let zone = "$ORIGIN example.test.\n@ 3600 IN SOA ns1.example.test. hostmaster.example.test. 2026112501 3600 600 604800 300\n@ 3600 IN NS ns1.example.test.\nns1 3600 IN A 192.0.2.1\nwww 300 IN A 192.0.2.42\n";
    let config = r#"
listen_addrs_ipv4 = ["127.0.0.1"]

[tls_cert]
path = "cert.pem"
private_key = "cert-key.pem"
endpoint_name = "localhost"

[[zones]]
zone = "example.test"
zone_type = "Primary"

[zones.stores]
type = "file"
zone_path = "example.test.zone"
"#;
    let generated_cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
        .expect("generate localhost test certificate");
    let cert_pem = generated_cert.cert.pem();
    let key_pem = generated_cert.key_pair.serialize_pem();
    let server = TestServer::start_temporary(
        config,
        &[
            ("example.test.zone", zone),
            ("cert.pem", &cert_pem),
            ("cert-key.pem", &key_pem),
        ],
    );
    let port = server.ports.get_v4(Protocol::H3).expect("H3 listener");

    let root_certificates = {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(generated_cert.cert.der().clone())
            .expect("add generated test root");
        roots
    };
    let client_config =
        rustls::ClientConfig::builder_with_provider(Arc::new(hickory_net::tls::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("configure TLS versions")
            .with_root_certificates(root_certificates)
            .with_no_client_auth();

    let mut client = H3ClientStream::builder()
        .crypto_config(client_config)
        .build(
            SocketAddr::from(([127, 0, 0, 1], port)),
            Arc::from("localhost"),
            Arc::from("/dns-query"),
        )
        .await
        .expect("connect using DoH3");
    let mut query = Message::query();
    query.add_query(Query::query(
        Name::from_str("www.example.test.").unwrap(),
        RecordType::A,
    ));
    let response = client
        .send_message(DnsRequest::new(query, DnsRequestOptions::default()))
        .first_answer()
        .await
        .expect("DoH3 DNS response");
    assert!(response.answers().iter().any(|record| {
        matches!(record.data(), RData::A(address) if *address == hickory_proto::rr::rdata::A(Ipv4Addr::new(192, 0, 2, 42)))
    }));
}

#[tokio::test]
#[cfg(all(feature = "__dnssec", feature = "sqlite"))]
async fn signed_axfr_stream_verifies_with_independent_dig_client() {
    let secret = "test_secret_key_for_metrics_tests";
    let secret_b64 = "dGVzdF9zZWNyZXRfa2V5X2Zvcl9tZXRyaWNzX3Rlc3Rz";
    let mut zone = String::from(
        "$ORIGIN example.test.\n@ 3600 IN SOA ns1.example.test. hostmaster.example.test. 2026112501 3600 600 604800 300\n@ 3600 IN NS ns1.example.test.\nns1 3600 IN A 192.0.2.1\n",
    );
    for i in 0..80 {
        zone.push_str(&format!("host{i} 300 IN A 192.0.2.{}\n", i % 250 + 1));
    }
    let config = r#"
listen_addrs_ipv4 = ["127.0.0.1"]

[[zones]]
zone = "example.test"
zone_type = "Primary"
axfr_policy = "AllowSigned"

[zones.stores]
type = "sqlite"
zone_path = "example.test.zone"
journal_path = "example.test.jrnl"
allow_update = true

[[zones.stores.tsig_keys]]
name = "transfer.example.test."
key_file = "transfer.key"
algorithm = "hmac-sha256"
"#;
    let server = TestServer::start_temporary(
        config,
        &[("example.test.zone", &zone), ("transfer.key", secret)],
    );
    let port = server.ports.get_v4(Protocol::Tcp).expect("TCP listener");

    let unsigned = Command::new("dig")
        .args([
            "+tcp",
            "@127.0.0.1",
            "-p",
            &port.to_string(),
            "example.test",
            "AXFR",
            "+time=3",
            "+tries=1",
        ])
        .output()
        .expect("dig is required for independent AXFR interoperability testing");
    let unsigned_output = String::from_utf8_lossy(&unsigned.stdout);
    assert!(
        unsigned_output.contains("Transfer failed"),
        "{unsigned_output}"
    );

    let signed = Command::new("dig")
        .args([
            "+tcp",
            "@127.0.0.1",
            "-p",
            &port.to_string(),
            "-y",
            &format!("hmac-sha256:transfer.example.test.:{secret_b64}"),
            "example.test",
            "AXFR",
            "+time=3",
            "+tries=1",
        ])
        .output()
        .expect("run signed AXFR with dig");
    let signed_output = String::from_utf8_lossy(&signed.stdout);
    assert!(
        signed.status.success(),
        "{}\n{}",
        signed_output,
        String::from_utf8_lossy(&signed.stderr)
    );
    assert!(
        !signed_output.contains("Couldn't verify signature"),
        "{signed_output}"
    );
    assert!(
        signed_output.contains("host79.example.test."),
        "{signed_output}"
    );
    assert!(
        signed_output.contains("XFR size: 84 records"),
        "{signed_output}"
    );
}

#[tokio::test]
#[cfg(feature = "sqlite")]
async fn hickory_axfr_client_consumes_multipart_transfer() {
    let mut zone = String::from(
        "$ORIGIN example.test.\n@ 3600 IN SOA ns1.example.test. hostmaster.example.test. 2026112501 3600 600 604800 300\n@ 3600 IN NS ns1.example.test.\nns1 3600 IN A 192.0.2.1\n",
    );
    for index in 0..80 {
        zone.push_str(&format!(
            "host{index} 300 IN A 192.0.2.{}\n",
            index % 250 + 1
        ));
    }
    let config = r#"
listen_addrs_ipv4 = ["127.0.0.1"]

[[zones]]
zone = "example.test"
zone_type = "Primary"
axfr_policy = "AllowAll"

[zones.stores]
type = "sqlite"
zone_path = "example.test.zone"
journal_path = "example.test.jrnl"
"#;
    let server = TestServer::start_temporary(config, &[("example.test.zone", &zone)]);
    let port = server.ports.get_v4(Protocol::Tcp).expect("TCP listener");
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let (connect, sender) = TcpClientStream::new(address, None, None, TokioRuntimeProvider::new());
    let stream = connect.await.expect("connect AXFR client");
    let (mut client, background) = Client::<TokioRuntimeProvider>::new(stream, sender);
    tokio::spawn(background);

    let mut transfer = client.zone_transfer(Name::from_str("example.test.").unwrap(), None);
    let mut records = Vec::new();
    while let Some(response) = transfer.next().await {
        records.extend(
            response
                .expect("valid AXFR response message")
                .answers()
                .iter()
                .cloned(),
        );
    }
    assert_eq!(
        records.len(),
        84,
        "both SOA boundaries and all records included"
    );
    assert_eq!(records.first().unwrap().record_type(), RecordType::SOA);
    assert_eq!(records.last().unwrap().record_type(), RecordType::SOA);
    assert!(records.iter().any(|record| {
        record.name() == &Name::from_str("host79.example.test.").unwrap()
            && record.record_type() == RecordType::A
    }));
}

#[tokio::test]
#[cfg(feature = "sqlite")]
async fn file_store_axfr_peer_acl_refuses_unlisted_client() {
    let zone = "$ORIGIN example.test.\n@ 3600 IN SOA ns1.example.test. hostmaster.example.test. 2026112501 3600 600 604800 300\n@ 3600 IN NS ns1.example.test.\nns1 3600 IN A 192.0.2.1\n";
    let config = r#"
listen_addrs_ipv4 = ["127.0.0.1"]

[[zones]]
zone = "example.test"
zone_type = "Primary"
axfr_policy = "AllowAll"

[zones.stores]
type = "file"
zone_path = "example.test.zone"
allowed_transfer_peers = ["192.0.2.44"]
"#;
    let server = TestServer::start_temporary(config, &[("example.test.zone", zone)]);
    let port = server.ports.get_v4(Protocol::Tcp).expect("TCP listener");
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let (connect, sender) = TcpClientStream::new(address, None, None, TokioRuntimeProvider::new());
    let stream = connect.await.expect("connect AXFR client");
    let (mut client, background) = Client::<TokioRuntimeProvider>::new(stream, sender);
    tokio::spawn(background);
    let mut transfer = client.zone_transfer(Name::from_str("example.test.").unwrap(), None);
    let refused = transfer
        .next()
        .await
        .expect("peer ACL refusal response")
        .expect("peer ACL returns a valid DNS response");
    assert_eq!(refused.response_code(), ResponseCode::Refused);
}

#[tokio::test]
#[cfg(feature = "sqlite")]
#[ignore = "requires an isolated BIND server at HICKORY_AXFR_INTEROP_ADDR"]
async fn hickory_axfr_client_interoperates_with_independent_bind() {
    let address = std::env::var("HICKORY_AXFR_INTEROP_ADDR")
        .expect("set HICKORY_AXFR_INTEROP_ADDR to the isolated BIND TCP endpoint")
        .parse::<SocketAddr>()
        .expect("valid AXFR server socket address");
    let (connect, sender) = TcpClientStream::new(address, None, None, TokioRuntimeProvider::new());
    let stream = connect.await.expect("connect to independent AXFR primary");
    let (mut client, background) = Client::<TokioRuntimeProvider>::new(stream, sender);
    tokio::spawn(background);

    let mut transfer = client.zone_transfer(Name::from_str("interop.test.").unwrap(), None);
    let mut records = Vec::new();
    while let Some(response) = transfer.next().await {
        records.extend(
            response
                .expect("valid independent BIND AXFR response")
                .answers()
                .iter()
                .cloned(),
        );
    }
    assert_eq!(records.first().unwrap().record_type(), RecordType::SOA);
    assert_eq!(records.last().unwrap().record_type(), RecordType::SOA);
    assert!(records.iter().any(|record| {
        record.name() == &Name::from_str("www.interop.test.").unwrap()
            && record.record_type() == RecordType::A
    }));
}

#[tokio::test]
#[cfg(all(feature = "__dnssec", feature = "sqlite"))]
async fn signed_axfr_is_supported_for_file_backed_zones() {
    let secret = "file_store_axfr_test_secret";
    let secret_b64 = "ZmlsZV9zdG9yZV9heGZyX3Rlc3Rfc2VjcmV0";
    let zone = "$ORIGIN file.test.\n@ 300 IN SOA ns.file.test. hostmaster.file.test. 2026112501 3600 600 604800 300\n@ 300 IN NS ns.file.test.\nns 300 IN A 192.0.2.1\nwww 300 IN A 192.0.2.80\n";
    let config = r#"
listen_addrs_ipv4 = ["127.0.0.1"]

[[zones]]
zone = "file.test"
zone_type = "Primary"
axfr_policy = "AllowSigned"

[zones.stores]
type = "file"
zone_path = "file.test.zone"

[[zones.stores.tsig_keys]]
name = "transfer.file.test."
key_file = "transfer.key"
algorithm = "hmac-sha256"
"#;
    let server = TestServer::start_temporary(
        config,
        &[("file.test.zone", zone), ("transfer.key", secret)],
    );
    let port = server.ports.get_v4(Protocol::Tcp).expect("TCP listener");
    let unsigned = Command::new("dig")
        .args([
            "+tcp",
            "@127.0.0.1",
            "-p",
            &port.to_string(),
            "file.test",
            "AXFR",
            "+time=3",
            "+tries=1",
        ])
        .output()
        .expect("dig is required for independent TSIG AXFR testing");
    assert!(
        String::from_utf8_lossy(&unsigned.stdout).contains("Transfer failed"),
        "unsigned file-store AXFR must be refused"
    );

    let invalid = Command::new("dig")
        .args([
            "+tcp",
            "@127.0.0.1",
            "-p",
            &port.to_string(),
            "-y",
            "hmac-sha256:transfer.file.test.:d3Jvbmdfc2VjcmV0",
            "file.test",
            "AXFR",
            "+time=3",
            "+tries=1",
        ])
        .output()
        .expect("run invalidly signed file-store AXFR");
    assert!(
        String::from_utf8_lossy(&invalid.stdout).contains("Transfer failed"),
        "incorrect TSIG secret must not transfer a file-backed zone"
    );

    let signed = Command::new("dig")
        .args([
            "+tcp",
            "@127.0.0.1",
            "-p",
            &port.to_string(),
            "-y",
            &format!("hmac-sha256:transfer.file.test.:{secret_b64}"),
            "file.test",
            "AXFR",
            "+time=3",
            "+tries=1",
        ])
        .output()
        .expect("run signed file-store AXFR");
    let output = String::from_utf8_lossy(&signed.stdout);
    assert!(signed.status.success(), "{output}");
    assert!(output.contains("www.file.test."), "{output}");
    assert!(!output.contains("Couldn't verify signature"), "{output}");
}

#[tokio::test]
#[cfg(feature = "sqlite")]
async fn ixfr_current_serial_succeeds_and_stale_serial_is_refused_safely() {
    let zone = "$ORIGIN example.test.\n@ 3600 IN SOA ns1.example.test. hostmaster.example.test. 2026112501 3600 600 604800 300\n@ 3600 IN NS ns1.example.test.\nns1 3600 IN A 192.0.2.1\n";
    let secret = "test_secret_key_for_metrics_tests";
    let secret_b64 = "dGVzdF9zZWNyZXRfa2V5X2Zvcl9tZXRyaWNzX3Rlc3Rz";
    let config = r#"
listen_addrs_ipv4 = ["127.0.0.1"]

[[zones]]
zone = "example.test"
zone_type = "Primary"
axfr_policy = "AllowAll"

[zones.stores]
type = "sqlite"
zone_path = "example.test.zone"
journal_path = "example.test.jrnl"
allow_update = true

[[zones.stores.tsig_keys]]
name = "transfer.example.test."
key_file = "transfer.key"
algorithm = "hmac-sha256"
"#;
    let server = TestServer::start_temporary(
        config,
        &[("example.test.zone", zone), ("transfer.key", secret)],
    );
    let port = server.ports.get_v4(Protocol::Tcp).expect("TCP listener");
    let query_ixfr = |serial: &str| {
        Command::new("dig")
            .args([
                "+tcp",
                "@127.0.0.1",
                "-p",
                &port.to_string(),
                "example.test",
                &format!("IXFR={serial}"),
                "+time=3",
                "+tries=1",
            ])
            .output()
            .expect("dig is required for independent IXFR interoperability testing")
    };
    let current = query_ixfr("2026112501");
    let current_output = String::from_utf8_lossy(&current.stdout);
    assert!(current.status.success(), "{current_output}");
    assert!(current_output.contains("2026112501"), "{current_output}");
    assert!(
        current_output.contains("XFR size: 1 record"),
        "{current_output}"
    );

    let update = format!(
        "server 127.0.0.1 {port}\nzone example.test.\nupdate add newhost.example.test. 300 A 192.0.2.2\nsend\n"
    );
    let mut nsupdate = Command::new("nsupdate")
        .args([
            "-v",
            "-y",
            &format!("hmac-sha256:transfer.example.test.:{secret_b64}"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("nsupdate is required for IXFR history test");
    nsupdate
        .stdin
        .take()
        .expect("nsupdate stdin")
        .write_all(update.as_bytes())
        .expect("send authenticated update");
    let update = nsupdate.wait_with_output().expect("wait for nsupdate");
    assert!(
        update.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&update.stdout),
        String::from_utf8_lossy(&update.stderr)
    );

    let stale = query_ixfr("2026112501");
    let stale_output = String::from_utf8_lossy(&stale.stdout);
    assert!(stale_output.contains("Transfer failed"), "{stale_output}");
    assert!(!stale_output.contains("timed out"), "{stale_output}");
    assert!(
        !stale_output.contains("newhost.example.test."),
        "{stale_output}"
    );
}

#[tokio::test]
async fn notify_acknowledges_local_zone_and_rejects_unknown_zone() {
    let zone = "$ORIGIN example.test.\n@ 3600 IN SOA ns1.example.test. hostmaster.example.test. 1 3600 600 604800 300\n@ 3600 IN NS ns1.example.test.\nns1 3600 IN A 192.0.2.1\n";
    let config = r#"
listen_addrs_ipv4 = ["127.0.0.1"]

[[zones]]
zone = "example.test"
zone_type = "Primary"
file = "example.test.zone"
"#;
    let server = TestServer::start_temporary(config, &[("example.test.zone", zone)]);
    let port = server.ports.get_v4(Protocol::Tcp).expect("TCP listener");
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let (future, sender) = TcpClientStream::new(addr, None, None, TokioRuntimeProvider::new());
    let stream = future.await.expect("connect local test DNS server");
    let (mut client, background) = Client::<TokioRuntimeProvider>::new(stream, sender);
    tokio::spawn(background);

    let accepted = client
        .notify(
            Name::from_str("example.test.").unwrap(),
            DNSClass::IN,
            RecordType::SOA,
            None::<hickory_proto::rr::RecordSet>,
        )
        .await
        .expect("receive NOTIFY acknowledgement");
    assert_eq!(accepted.response_code(), ResponseCode::NoError);

    let refused = client
        .notify(
            Name::from_str("missing.other.test.").unwrap(),
            DNSClass::IN,
            RecordType::SOA,
            None::<hickory_proto::rr::RecordSet>,
        )
        .await
        .expect("receive unknown-zone NOTIFY response");
    assert_eq!(refused.response_code(), ResponseCode::NotAuth);
}

#[tokio::test]
#[cfg(feature = "__dnssec")]
async fn notify_requires_and_verifies_configured_file_store_tsig() {
    let zone = "$ORIGIN signed-notify.test.\n@ 300 IN SOA ns.signed-notify.test. hostmaster.signed-notify.test. 1 3600 600 604800 300\n@ 300 IN NS ns.signed-notify.test.\nns 300 IN A 192.0.2.1\n";
    let secret = "valid-notify-test-secret-material";
    let config = r#"
listen_addrs_ipv4 = ["127.0.0.1"]

[[zones]]
zone = "signed-notify.test"
zone_type = "Primary"

[zones.stores]
type = "file"
zone_path = "notify.zone"

[[zones.stores.tsig_keys]]
name = "notify-key."
key_file = "notify.key"
algorithm = "hmac-sha256"
"#;
    let server =
        TestServer::start_temporary(config, &[("notify.zone", zone), ("notify.key", secret)]);
    let port = server.ports.get_v4(Protocol::Tcp).expect("TCP listener");
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));

    let (connect, sender) = TcpClientStream::new(address, None, None, TokioRuntimeProvider::new());
    let stream = connect.await.expect("connect unsigned NOTIFY client");
    let (mut unsigned, background) = Client::<TokioRuntimeProvider>::new(stream, sender);
    tokio::spawn(background);
    let response = unsigned
        .notify(
            Name::from_str("signed-notify.test.").unwrap(),
            DNSClass::IN,
            RecordType::SOA,
            None::<hickory_proto::rr::RecordSet>,
        )
        .await
        .expect("receive unsigned NOTIFY refusal");
    assert_eq!(response.response_code(), ResponseCode::Refused);

    let make_signed_client = |key: &'static [u8]| async move {
        let signer = TSigner::new(
            key.to_vec(),
            TsigAlgorithm::HmacSha256,
            Name::from_str("notify-key.").unwrap(),
            300,
        )
        .unwrap();
        let (connect, sender) =
            TcpClientStream::new(address, None, None, TokioRuntimeProvider::new());
        let stream = connect.await.expect("connect signed NOTIFY client");
        let (client, background) = Client::<TokioRuntimeProvider>::from_sender(
            DnsMultiplexer::new(stream, sender).with_signer(signer),
        );
        tokio::spawn(background);
        client
    };

    let mut valid = make_signed_client(secret.as_bytes()).await;
    let response = valid
        .notify(
            Name::from_str("signed-notify.test.").unwrap(),
            DNSClass::IN,
            RecordType::SOA,
            None::<hickory_proto::rr::RecordSet>,
        )
        .await
        .expect("valid TSIG NOTIFY response verifies");
    assert_eq!(response.response_code(), ResponseCode::NoError);

    let mut invalid = make_signed_client(b"different-notify-secret-material").await;
    let result = invalid
        .notify(
            Name::from_str("signed-notify.test.").unwrap(),
            DNSClass::IN,
            RecordType::SOA,
            None::<hickory_proto::rr::RecordSet>,
        )
        .await;
    assert!(result.is_err(), "invalid request MAC must not be accepted");
}

#[tokio::test]
#[cfg(feature = "metrics")]
async fn primary_notifies_configured_secondary_after_zone_reload() {
    let zone = "$ORIGIN notify.test.\n@ 300 IN SOA ns.notify.test. hostmaster.notify.test. 1 3600 600 604800 300\n@ 300 IN NS ns.notify.test.\nns 300 IN A 192.0.2.1\n";
    let receiver_config = r#"
listen_addrs_ipv4 = ["127.0.0.1"]
[[zones]]
zone = "notify.test"
zone_type = "Primary"
file = "notify.zone"
"#;
    let receiver = TestServer::start_temporary(receiver_config, &[("notify.zone", zone)]);
    let receiver_port = receiver.ports.get_v4(Protocol::Tcp).expect("TCP listener");
    let primary_config = format!(
        r#"
listen_addrs_ipv4 = ["127.0.0.1"]
[[zones]]
zone = "notify.test"
zone_type = "Primary"
file = "notify.zone"
[[zones.notify_peers]]
address = "127.0.0.1:{receiver_port}"
"#
    );
    let primary = TestServer::start_temporary(&primary_config, &[("notify.zone", zone)]);
    std::thread::sleep(Duration::from_millis(100));
    let changed = zone.replace(" 1 3600", " 2 3600");
    primary.write_temporary_file("notify.zone", &changed);

    let metrics_port = receiver
        .ports
        .get_v4(ServerProtocol::PrometheusMetrics)
        .expect("metrics listener");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let metrics = reqwest::get(format!("http://127.0.0.1:{metrics_port}/"))
            .await
            .expect("scrape receiver metrics")
            .text()
            .await
            .expect("read receiver metrics");
        if metrics.lines().any(|line| {
            line.starts_with("hickory_request_operations_total{operation=\"notify\"}")
                && line
                    .split_whitespace()
                    .last()
                    .is_some_and(|value| value != "0")
        }) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "configured secondary did not receive a NOTIFY"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn accepted_notify_refreshes_secondary_by_axfr_and_preserves_last_known_good_on_failure() {
    let primary_zone = "$ORIGIN secondary.test.\n@ 300 IN SOA ns.secondary.test. hostmaster.secondary.test. 2 3600 600 604800 300\n@ 300 IN NS ns.secondary.test.\nns 300 IN A 192.0.2.1\nwww 300 IN A 192.0.2.22\n";
    let primary_config = r#"
listen_addrs_ipv4 = ["127.0.0.1"]
[[zones]]
zone = "secondary.test"
zone_type = "Primary"
axfr_policy = "AllowAll"
file = "primary.zone"
"#;
    let primary = TestServer::start_temporary(primary_config, &[("primary.zone", primary_zone)]);
    let primary_port = primary
        .ports
        .get_v4(Protocol::Tcp)
        .expect("primary TCP listener");
    let master = format!("127.0.0.1:{primary_port}");
    let (connect, sender) = TcpClientStream::new(
        SocketAddr::from((Ipv4Addr::LOCALHOST, primary_port)),
        None,
        None,
        TokioRuntimeProvider::new(),
    );
    let stream = connect
        .await
        .expect("connect directly to primary for AXFR sanity check");
    let (mut primary_client, background) = Client::<TokioRuntimeProvider>::new(stream, sender);
    tokio::spawn(background);
    let mut transfer =
        primary_client.zone_transfer(Name::from_str("secondary.test.").unwrap(), None);
    let mut transferred = Vec::new();
    while let Some(response) = transfer.next().await {
        transferred.extend(
            response
                .expect("primary AXFR response parses")
                .answers()
                .iter()
                .cloned(),
        );
    }
    assert_eq!(transferred.len(), 5, "complete SOA-bounded AXFR");
    assert_eq!(
        transferred.first().and_then(|record| match record.data() {
            RData::SOA(soa) => Some(soa),
            _ => None,
        }),
        transferred.last().and_then(|record| match record.data() {
            RData::SOA(soa) => Some(soa),
            _ => None,
        }),
        "AXFR boundary SOAs must be identical"
    );
    let secondary_zone = "$ORIGIN secondary.test.\n@ 300 IN SOA ns.secondary.test. hostmaster.secondary.test. 1 3600 600 604800 300\n@ 300 IN NS ns.secondary.test.\nns 300 IN A 192.0.2.1\nwww 300 IN A 192.0.2.11\n";
    let secondary_config = format!(
        r#"
listen_addrs_ipv4 = ["127.0.0.1"]
[[zones]]
zone = "secondary.test"
zone_type = "Secondary"
file = "secondary.zone"
[[zones.masters]]
address = "{master}"
"#
    );
    let secondary = TestServer::start_temporary_with_zone_writes(
        &secondary_config,
        &[("secondary.zone", secondary_zone)],
    );
    let secondary_port = secondary
        .ports
        .get_v4(Protocol::Udp)
        .expect("secondary UDP listener");
    let secondary_tcp_port = secondary
        .ports
        .get_v4(Protocol::Tcp)
        .expect("secondary TCP listener");
    let stream = UdpClientStream::builder(
        SocketAddr::from((Ipv4Addr::LOCALHOST, secondary_port)),
        TokioRuntimeProvider::new(),
    )
    .build();
    let (mut client, background) = Client::<TokioRuntimeProvider>::from_sender(stream);
    tokio::spawn(background);
    let name = Name::from_str("www.secondary.test.").unwrap();
    let before = client
        .query(name.clone(), DNSClass::IN, RecordType::A)
        .await
        .unwrap();
    assert!(
        before.answers().iter().any(|record| {
            matches!(record.data(), RData::A(address) if *address == A::new(192, 0, 2, 22))
        }),
        "secondary must complete its first AXFR before serving queries"
    );

    let changed_primary = primary_zone
        .replace(" 2 3600", " 3 3600")
        .replace("192.0.2.22", "192.0.2.33");
    primary.write_temporary_file("primary.zone", &changed_primary);
    let primary_udp = primary
        .ports
        .get_v4(Protocol::Udp)
        .expect("primary UDP listener");
    let primary_stream = UdpClientStream::builder(
        SocketAddr::from((Ipv4Addr::LOCALHOST, primary_udp)),
        TokioRuntimeProvider::new(),
    )
    .build();
    let (mut primary_client, background) =
        Client::<TokioRuntimeProvider>::from_sender(primary_stream);
    tokio::spawn(background);
    let primary_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let response = primary_client
            .query(
                Name::from_str("secondary.test.").unwrap(),
                DNSClass::IN,
                RecordType::SOA,
            )
            .await
            .unwrap();
        if response
            .answers()
            .iter()
            .any(|record| matches!(record.data(), RData::SOA(soa) if soa.serial() == 3))
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < primary_deadline,
            "primary did not reload serial 3"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let (connect, sender) = TcpClientStream::new(
        SocketAddr::from((Ipv4Addr::LOCALHOST, secondary_tcp_port)),
        None,
        None,
        TokioRuntimeProvider::new(),
    );
    let stream = connect.await.expect("connect to secondary for NOTIFY");
    let (mut notifier, background) = Client::<TokioRuntimeProvider>::new(stream, sender);
    tokio::spawn(background);
    let response = notifier
        .notify(
            Name::from_str("secondary.test.").unwrap(),
            DNSClass::IN,
            RecordType::SOA,
            None::<hickory_proto::rr::RecordSet>,
        )
        .await
        .expect("secondary acknowledges configured master NOTIFY");
    assert_eq!(response.response_code(), ResponseCode::NoError);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let response = client
            .query(name.clone(), DNSClass::IN, RecordType::A)
            .await
            .unwrap();
        if response.answers().iter().any(|record| {
        matches!(record.data(), RData::A(address) if *address == A::new(192, 0, 2, 33))
        }) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "secondary did not serve the complete AXFR after accepted NOTIFY; installed file: {}",
            secondary.read_temporary_file("secondary.zone")
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // A failed transfer is retried, but a fresh secondary must continue
    // serving its last-known-good file throughout the failure.
    let denied_zone = primary_zone
        .replace(" 2 3600", " 4 3600")
        .replace("192.0.2.22", "192.0.2.44");
    let denied_primary_config = primary_config.replace("AllowAll", "Deny");
    let denied_primary =
        TestServer::start_temporary(&denied_primary_config, &[("primary.zone", &denied_zone)]);
    let denied_port = denied_primary
        .ports
        .get_v4(Protocol::Tcp)
        .expect("denied primary TCP listener");
    let failed_secondary_config = format!(
        r#"
listen_addrs_ipv4 = ["127.0.0.1"]
[[zones]]
zone = "secondary.test"
zone_type = "Secondary"
file = "secondary.zone"
[[zones.masters]]
address = "127.0.0.1:{denied_port}"
"#
    );
    let failed_secondary = TestServer::start_temporary_with_zone_writes(
        &failed_secondary_config,
        &[("secondary.zone", secondary_zone)],
    );
    let failed_udp_port = failed_secondary
        .ports
        .get_v4(Protocol::Udp)
        .expect("failed secondary UDP listener");
    let failed_tcp_port = failed_secondary
        .ports
        .get_v4(Protocol::Tcp)
        .expect("failed secondary TCP listener");
    let failed_stream = UdpClientStream::builder(
        SocketAddr::from((Ipv4Addr::LOCALHOST, failed_udp_port)),
        TokioRuntimeProvider::new(),
    )
    .build();
    let (mut failed_query_client, background) =
        Client::<TokioRuntimeProvider>::from_sender(failed_stream);
    tokio::spawn(background);
    let failed_before = failed_query_client
        .query(
            Name::from_str("www.secondary.test.").unwrap(),
            DNSClass::IN,
            RecordType::A,
        )
        .await
        .unwrap();
    assert!(failed_before.answers().iter().any(|record| {
        matches!(record.data(), RData::A(address) if *address == A::new(192, 0, 2, 11))
    }));
    let (connect, sender) = TcpClientStream::new(
        SocketAddr::from((Ipv4Addr::LOCALHOST, failed_tcp_port)),
        None,
        None,
        TokioRuntimeProvider::new(),
    );
    let stream = connect.await.expect("connect for failed-transfer NOTIFY");
    let (mut notifier, background) = Client::<TokioRuntimeProvider>::new(stream, sender);
    tokio::spawn(background);
    let response = notifier
        .notify(
            Name::from_str("secondary.test.").unwrap(),
            DNSClass::IN,
            RecordType::SOA,
            None::<hickory_proto::rr::RecordSet>,
        )
        .await
        .expect("failed secondary still acknowledges valid NOTIFY");
    assert_eq!(response.response_code(), ResponseCode::NoError);
    tokio::time::sleep(Duration::from_secs(2)).await;
    let failed_after = failed_query_client
        .query(
            Name::from_str("www.secondary.test.").unwrap(),
            DNSClass::IN,
            RecordType::A,
        )
        .await
        .unwrap();
    assert!(failed_after.answers().iter().any(|record| {
        matches!(record.data(), RData::A(address) if *address == A::new(192, 0, 2, 11))
    }));
}

#[tokio::test]
async fn expired_secondary_fails_closed_after_primary_is_unavailable() {
    let zone = "$ORIGIN expire.test.\n$TTL 30\n@ IN SOA ns.expire.test. hostmaster.expire.test. 1 1 1 3 1\n@ IN NS ns.expire.test.\nns IN A 192.0.2.1\nwww IN A 192.0.2.9\n";
    let primary_config = r#"
listen_addrs_ipv4 = ["127.0.0.1"]
[[zones]]
zone = "expire.test"
zone_type = "Primary"
axfr_policy = "AllowAll"
file = "primary.zone"
"#;
    let primary = TestServer::start_temporary(primary_config, &[("primary.zone", zone)]);
    let primary_port = primary
        .ports
        .get_v4(Protocol::Tcp)
        .expect("primary TCP listener");
    let secondary_config = format!(
        r#"
listen_addrs_ipv4 = ["127.0.0.1"]
[[zones]]
zone = "expire.test"
zone_type = "Secondary"
file = "secondary.zone"
[[zones.masters]]
address = "127.0.0.1:{primary_port}"
"#
    );
    let secondary = TestServer::start_temporary_with_zone_writes(
        &secondary_config,
        &[("secondary.zone", zone)],
    );
    let secondary_port = secondary
        .ports
        .get_v4(Protocol::Udp)
        .expect("secondary UDP listener");
    let stream = UdpClientStream::builder(
        SocketAddr::from((Ipv4Addr::LOCALHOST, secondary_port)),
        TokioRuntimeProvider::new(),
    )
    .build();
    let (mut client, background) = Client::<TokioRuntimeProvider>::from_sender(stream);
    tokio::spawn(background);
    let name = Name::from_str("www.expire.test.").unwrap();
    let initial = query_message(&mut client, name.clone(), RecordType::A)
        .await
        .expect("initial answer");
    assert!(initial.answers().iter().any(|record| {
        matches!(record.data(), RData::A(address) if *address == A::new(192, 0, 2, 9))
    }));

    let mut primary = primary;
    primary.stop();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    loop {
        let response = query_message(&mut client, name.clone(), RecordType::A)
            .await
            .expect("secondary DNS response");
        if response.response_code() == ResponseCode::ServFail {
            assert!(
                response.answers().is_empty(),
                "expired zone must not leak stale records"
            );
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "secondary continued serving after SOA expire elapsed"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

#[tokio::test]
async fn secondary_refreshes_from_primary_on_soa_timer_without_notify() {
    let primary_zone = "$ORIGIN timer-secondary.test.\n@ 60 IN SOA ns.timer-secondary.test. hostmaster.timer-secondary.test. 1 1 1 30 1\n@ 60 IN NS ns.timer-secondary.test.\nns 60 IN A 192.0.2.1\nwww 60 IN A 192.0.2.11\n";
    let primary_config = r#"
listen_addrs_ipv4 = ["127.0.0.1"]
[[zones]]
zone = "timer-secondary.test"
zone_type = "Primary"
axfr_policy = "AllowAll"
file = "primary.zone"
"#;
    let primary = TestServer::start_temporary(primary_config, &[("primary.zone", primary_zone)]);
    let primary_tcp = primary
        .ports
        .get_v4(Protocol::Tcp)
        .expect("primary TCP listener");
    let secondary_zone = primary_zone
        .replace(" 1 1 1 30", " 0 1 1 30")
        .replace("192.0.2.11", "192.0.2.10");
    let secondary_config = format!(
        r#"
listen_addrs_ipv4 = ["127.0.0.1"]
[[zones]]
zone = "timer-secondary.test"
zone_type = "Secondary"
file = "secondary.zone"
[[zones.masters]]
address = "127.0.0.1:{primary_tcp}"
"#
    );
    let secondary = TestServer::start_temporary_with_zone_writes(
        &secondary_config,
        &[("secondary.zone", &secondary_zone)],
    );
    let secondary_udp = secondary
        .ports
        .get_v4(Protocol::Udp)
        .expect("secondary UDP listener");
    let mut secondary_client = {
        let stream = UdpClientStream::builder(
            SocketAddr::from((Ipv4Addr::LOCALHOST, secondary_udp)),
            TokioRuntimeProvider::new(),
        )
        .build();
        let (client, background) = Client::<TokioRuntimeProvider>::from_sender(stream);
        tokio::spawn(background);
        client
    };

    let updated = primary_zone
        .replace(" 1 1 1 30", " 2 1 1 30")
        .replace("192.0.2.11", "192.0.2.22");
    primary.write_temporary_file("primary.zone", &updated);
    let primary_stream = UdpClientStream::builder(
        SocketAddr::from((
            Ipv4Addr::LOCALHOST,
            primary.ports.get_v4(Protocol::Udp).unwrap(),
        )),
        TokioRuntimeProvider::new(),
    )
    .build();
    let (mut primary_client, background) =
        Client::<TokioRuntimeProvider>::from_sender(primary_stream);
    tokio::spawn(background);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    loop {
        let response = primary_client
            .query(
                Name::from_str("timer-secondary.test.").unwrap(),
                DNSClass::IN,
                RecordType::SOA,
            )
            .await
            .unwrap();
        if response
            .answers()
            .iter()
            .any(|record| matches!(record.data(), RData::SOA(soa) if soa.serial() == 2))
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "primary did not reload updated serial"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    loop {
        let response = secondary_client
            .query(
                Name::from_str("www.timer-secondary.test.").unwrap(),
                DNSClass::IN,
                RecordType::A,
            )
            .await
            .unwrap();
        if response.answers().iter().any(|record| matches!(record.data(), RData::A(address) if *address == A::new(192, 0, 2, 22))) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "secondary did not refresh at the SOA refresh interval"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
#[cfg(feature = "__dnssec")]
async fn primary_notifies_with_tsig_and_retries_unresponsive_peer() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    use tokio::io::AsyncReadExt;

    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind unresponsive NOTIFY test peer");
    let address = listener.local_addr().unwrap();
    let received = Arc::new(AtomicUsize::new(0));
    let saw_tsig = Arc::new(AtomicBool::new(false));
    let peer_received = received.clone();
    let peer_saw_tsig = saw_tsig.clone();
    let peer_task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.expect("accept NOTIFY retry");
            let received = peer_received.clone();
            let saw_tsig = peer_saw_tsig.clone();
            tokio::spawn(async move {
                let Ok(length) = stream.read_u16().await else {
                    return;
                };
                let mut bytes = vec![0; usize::from(length)];
                if stream.read_exact(&mut bytes).await.is_err() {
                    return;
                }
                if let Ok(message) = hickory_proto::op::Message::from_vec(&bytes) {
                    if message.signature().is_some() {
                        saw_tsig.store(true, Ordering::Relaxed);
                    }
                    received.fetch_add(1, Ordering::Relaxed);
                }
                // Deliberately never acknowledge the notification. The sender must time out
                // and retry; each connection closes when that attempt's deadline expires.
                tokio::time::sleep(Duration::from_secs(30)).await;
            });
        }
    });

    let zone = "$ORIGIN signed-notify.test.\n@ 300 IN SOA ns.signed-notify.test. hostmaster.signed-notify.test. 1 3600 600 604800 300\n@ 300 IN NS ns.signed-notify.test.\nns 300 IN A 192.0.2.1\n";
    let config = format!(
        r#"
listen_addrs_ipv4 = ["127.0.0.1"]
[[zones]]
zone = "signed-notify.test"
zone_type = "Primary"
file = "notify.zone"
[[zones.notify_peers]]
address = "{address}"
tsig = {{ name = "notify-key.", key_file = "notify.key", algorithm = "hmac-sha256" }}
"#
    );
    let primary = TestServer::start_temporary(
        &config,
        &[
            ("notify.zone", zone),
            ("notify.key", "test-notify-secret-32-bytes-long"),
        ],
    );
    std::thread::sleep(Duration::from_millis(100));
    let changed = zone.replace(" 1 3600", " 2 3600");
    primary.write_temporary_file("notify.zone", &changed);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(12);
    while received.load(Ordering::Relaxed) < 3 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "sender did not retry three timed-out NOTIFY requests"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        saw_tsig.load(Ordering::Relaxed),
        "outbound NOTIFY omitted TSIG"
    );

    let port = primary
        .ports
        .get_v4(Protocol::Tcp)
        .expect("primary TCP listener");
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let (connect, sender) = TcpClientStream::new(addr, None, None, TokioRuntimeProvider::new());
    let stream = connect.await.expect("connect primary while NOTIFY retries");
    let (mut client, background) = Client::<TokioRuntimeProvider>::new(stream, sender);
    tokio::spawn(background);
    let response = client
        .query(
            Name::from_str("signed-notify.test.").unwrap(),
            DNSClass::IN,
            RecordType::SOA,
        )
        .await
        .expect("primary remains available during NOTIFY retry backoff");
    assert_eq!(response.response_code(), ResponseCode::NoError);
    peer_task.abort();
}

#[tokio::test]
async fn test_example_toml_startup() {
    subscribe();
    let provider = TokioRuntimeProvider::new();
    let server = TestServer::start("example.toml");
    let tcp_port = server.ports.get_v4(Protocol::Tcp);

    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, tcp_port.expect("no tcp_port")));
    let (future, sender) = TcpClientStream::new(addr, None, None, provider.clone());
    let stream = future.await.expect("failed to create tcp stream");
    let (mut client, bg) = Client::<TokioRuntimeProvider>::new(stream, sender);
    tokio::spawn(bg);

    query_a(&mut client).await;

    // just tests that multiple queries work
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, tcp_port.expect("no tcp_port")));
    let (future, sender) = TcpClientStream::new(addr, None, None, provider.clone());
    let stream = future.await.expect("failed to create tcp stream");
    let (mut client, bg) = Client::<TokioRuntimeProvider>::new(stream, sender);
    tokio::spawn(bg);

    query_a(&mut client).await;
}

#[tokio::test]
async fn malformed_udp_packet_does_not_disrupt_authoritative_queries() {
    let server = TestServer::start("example.toml");
    let udp_port = server.ports.get_v4(Protocol::Udp).expect("no UDP port");
    let socket = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind UDP client");
    socket
        .send_to(&[0, 1, 2], (Ipv4Addr::LOCALHOST, udp_port))
        .await
        .expect("send short DNS packet");
    let mut response = [0u8; 512];
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(250),
            socket.recv(&mut response)
        )
        .await
        .is_err(),
        "packet without a DNS header must be dropped"
    );

    let tcp_port = server.ports.get_v4(Protocol::Tcp).expect("no TCP port");
    let provider = TokioRuntimeProvider::new();
    let (future, sender) = TcpClientStream::new(
        SocketAddr::from((Ipv4Addr::LOCALHOST, tcp_port)),
        None,
        None,
        provider.clone(),
    );
    let stream = future
        .await
        .expect("DNS server stopped after malformed packet");
    let (mut client, bg) = Client::<TokioRuntimeProvider>::new(stream, sender);
    tokio::spawn(bg);
    query_a(&mut client).await;
}

#[tokio::test]
async fn test_ipv4_only_toml_startup() {
    subscribe();
    let provider = TokioRuntimeProvider::new();
    let server = TestServer::start("ipv4_only.toml");
    let tcp_port = server.ports.get_v4(Protocol::Tcp);

    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, tcp_port.expect("no tcp_port")));
    let (future, sender) = TcpClientStream::new(addr, None, None, provider.clone());
    let stream = future.await.expect("failed to create tcp stream");
    let (mut client, bg) = Client::<TokioRuntimeProvider>::new(stream, sender);
    tokio::spawn(bg);

    // ipv4 should succeed
    query_a(&mut client).await;

    let addr = SocketAddr::from((Ipv6Addr::LOCALHOST, tcp_port.expect("no tcp_port")));
    let (future, _) = TcpClientStream::new(addr, None, None, provider.clone());
    assert!(future.await.is_err());
    //let (client, bg) = client.await.expect("client failed to connect");
    //tokio::spawn(bg);

    // ipv6 should fail
    // FIXME: probably need to send something for proper test... maybe use JoinHandle in tokio 0.2
    // assert!(client.await.is_err());
}

// TODO: this is commented out b/c at least on macOS, ipv4 will route properly to ipv6 only
//  listeners over the [::ffff:127.0.0.1] interface
//
// #[ignore]
// #[test]
// fn test_ipv6_only_toml_startup() {
//   named_test_harness("ipv6_only.toml", |socket_ports| {
//     let mut io_loop = Runtime::new().unwrap();
//     let tcp_port = socket_ports.get_v4(Protocol::Tcp);
//     let addr: SocketAddr = ("127.0.0.1", port).to_socket_addrs().unwrap().next().unwrap();
//     let (stream, sender) = TcpClientStream::new(addr);
//     let client = AsyncClient::new(stream, sender, None);
//     let mut client = io_loop.block_on(client).unwrap();
//
//     // ipv4 should fail
//     assert!(!query(&mut io_loop, client));
//
//     let addr: SocketAddr = ("::1", port).to_socket_addrs().unwrap().next().unwrap();
//     let (stream, sender) = TcpClientStream::new(addr);
//     let client = AsyncClient::new(stream, sender, None);
//     let mut client = io_loop.block_on(client).unwrap();
//
//     // ipv6 should succeed
//     assert!(query(&mut io_loop, client));
//
//     assert!(true);
//   })
// }

#[tokio::test]
async fn test_ipv4_and_ipv6_toml_startup() {
    subscribe();
    let provider = TokioRuntimeProvider::new();
    let server = TestServer::start("ipv4_and_ipv6.toml");
    let tcp_port = server.ports.get_v4(Protocol::Tcp);

    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, tcp_port.expect("no tcp_port")));
    let (future, sender) = TcpClientStream::new(addr, None, None, provider.clone());
    let stream = future.await.expect("failed to create tcp stream");
    let (mut client, bg) = Client::<TokioRuntimeProvider>::new(stream, sender);
    tokio::spawn(bg);

    // ipv4 should succeed
    query_a(&mut client).await;

    // Some containers have IPv6 disabled entirely. In that case the server's
    // IPv6 listener cannot be exercised from this host; retain the IPv4 check.
    if TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).is_err() {
        eprintln!("IPv6 loopback unavailable; IPv6 query requires a dual-stack test host");
        return;
    }

    let tcp_port = server.ports.get_v6(Protocol::Tcp);
    let addr = SocketAddr::from((Ipv6Addr::LOCALHOST, tcp_port.expect("no tcp_port")));
    let (future, sender) = TcpClientStream::new(addr, None, None, provider.clone());
    let stream = future.await.expect("failed to create tcp stream");
    let (mut client, bg) = Client::<TokioRuntimeProvider>::new(stream, sender);
    tokio::spawn(bg);

    // ipv6 should succeed
    query_a(&mut client).await;
}

#[tokio::test]
async fn test_nodata_where_name_exists() {
    subscribe();
    let provider = TokioRuntimeProvider::new();
    let server = TestServer::start("example.toml");
    let tcp_port = server.ports.get_v4(Protocol::Tcp);

    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, tcp_port.expect("no tcp_port")));
    let (future, sender) = TcpClientStream::new(addr, None, None, provider.clone());
    let stream = future.await.expect("failed to create tcp stream");
    let (mut client, bg) = Client::<TokioRuntimeProvider>::new(stream, sender);
    tokio::spawn(bg);

    let msg = client
        .query(
            Name::from_str("www.example.com.").unwrap(),
            DNSClass::IN,
            RecordType::SRV,
        )
        .await
        .unwrap();
    assert_eq!(msg.response_code(), ResponseCode::NoError);
    assert!(msg.answers().is_empty());
}

#[tokio::test]
async fn test_nxdomain_where_no_name_exists() {
    subscribe();
    let provider = TokioRuntimeProvider::new();
    let server = TestServer::start("example.toml");
    let tcp_port = server.ports.get_v4(Protocol::Tcp);

    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, tcp_port.expect("no tcp_port")));
    let (future, sender) = TcpClientStream::new(addr, None, None, provider.clone());
    let stream = future.await.expect("failed to create tcp stream");
    let (mut client, bg) = Client::<TokioRuntimeProvider>::new(stream, sender);
    tokio::spawn(bg);

    let msg = client
        .query(
            Name::from_str("nxdomain.example.com.").unwrap(),
            DNSClass::IN,
            RecordType::SRV,
        )
        .await
        .unwrap();
    assert_eq!(msg.response_code(), ResponseCode::NXDomain);
    assert!(msg.answers().is_empty());
}

#[tokio::test]
async fn test_server_continues_on_bad_data_udp() {
    subscribe();
    let provider = TokioRuntimeProvider::new();
    let server = TestServer::start("example.toml");
    let udp_port = server.ports.get_v4(Protocol::Udp);

    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, udp_port.expect("no udp_port")));
    let stream = UdpClientStream::builder(addr, provider.clone()).build();
    let (mut client, bg) = Client::<TokioRuntimeProvider>::from_sender(stream);
    tokio::spawn(bg);

    query_a(&mut client).await;

    // Send a bad packet, this should get rejected by the server
    let raw_socket = UdpSocket::bind(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0))
        .expect("couldn't bind raw");

    raw_socket
        .send_to(b"0xDEADBEEF", addr)
        .expect("raw send failed");

    // just tests that multiple queries work
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, udp_port.expect("no udp_port")));
    let stream = UdpClientStream::builder(addr, provider).build();
    let (mut client, bg) = Client::<TokioRuntimeProvider>::from_sender(stream);
    tokio::spawn(bg);

    query_a(&mut client).await;
}

#[tokio::test]
async fn test_server_continues_on_bad_data_tcp() {
    subscribe();
    let provider = TokioRuntimeProvider::new();
    let server = TestServer::start("example.toml");
    let tcp_port = server.ports.get_v4(Protocol::Tcp);

    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, tcp_port.expect("no tcp_port")));
    let (future, sender) = TcpClientStream::new(addr, None, None, provider.clone());
    let stream = future.await.expect("failed to create tcp stream");

    let (mut client, bg) = Client::<TokioRuntimeProvider>::new(stream, sender);
    tokio::spawn(bg);

    query_a(&mut client).await;

    // Send a bad packet, this should get rejected by the server
    let mut raw_socket = TcpStream::connect(addr).expect("couldn't bind raw");

    raw_socket
        .write_all(b"0xDEADBEEF")
        .expect("raw send failed");

    // just tests that multiple queries work
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, tcp_port.expect("no tcp_port")));
    let (future, sender) = TcpClientStream::new(addr, None, None, provider.clone());
    let stream = future.await.expect("failed to create tcp stream");
    let (mut client, bg) = Client::<TokioRuntimeProvider>::new(stream, sender);
    tokio::spawn(bg);

    query_a(&mut client).await;
}

#[tokio::test]
async fn protocol_admission_fanout_keeps_service_available() {
    subscribe();
    let server = TestServer::start_with_env(
        "example.toml",
        &[
            ("DNS_MAX_TCP_CONNECTIONS", "8"),
            ("DNS_MAX_INFLIGHT_UDP", "8"),
        ],
    );
    let tcp_addr = SocketAddr::from((
        Ipv4Addr::LOCALHOST,
        server.ports.get_v4(Protocol::Tcp).expect("no TCP port"),
    ));

    // Hold 96 idle TCP connections concurrently. The server should retain at
    // most eight DNS connection permits and close the excess before it can
    // consume all available file descriptors.
    let mut clients = Vec::new();
    for _ in 0..96 {
        clients.push(std::thread::spawn(move || {
            let Ok(mut stream) = TcpStream::connect_timeout(&tcp_addr, Duration::from_secs(3))
            else {
                return false;
            };
            std::thread::sleep(Duration::from_millis(250));
            stream
                .set_read_timeout(Some(Duration::from_millis(500)))
                .unwrap();
            let mut byte = [0u8; 1];
            matches!(stream.read(&mut byte), Ok(0))
        }));
    }
    let closed_before_request = clients
        .into_iter()
        .map(|client| client.join().expect("TCP load worker panicked"))
        .filter(|closed| *closed)
        .count();
    assert!(
        closed_before_request >= 32,
        "expected excess connections to be rejected, got {closed_before_request} closed"
    );

    let udp_port = server.ports.get_v4(Protocol::Udp).expect("no UDP port");
    let udp_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, udp_port));
    let flood = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind UDP flood client");
    let mut packet = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    packet.extend_from_slice(&[3, b'w', b'w', b'w', 7]);
    packet.extend_from_slice(b"example");
    packet.extend_from_slice(&[3]);
    packet.extend_from_slice(b"com");
    packet.extend_from_slice(&[0, 0, 1, 0, 1]);
    for _ in 0..32 {
        flood
            .send_to(&packet, udp_addr)
            .expect("send bounded UDP load");
    }
    drop(flood);
    std::thread::sleep(Duration::from_millis(50));

    // Both listeners remain usable after the combined burst; a normal UDP
    // query still gets the authoritative fixture answer within the deadline.
    let provider = TokioRuntimeProvider::new();
    let stream = UdpClientStream::builder(udp_addr, provider).build();
    let (mut client, bg) = Client::<TokioRuntimeProvider>::from_sender(stream);
    tokio::spawn(bg);
    tokio::time::timeout(Duration::from_secs(3), query_a(&mut client))
        .await
        .expect("DNS service did not recover after admission pressure");
}

#[tokio::test]
async fn axfr_for_external_zone_is_refused_without_upstream_contact() {
    subscribe();
    let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind fake upstream");
    upstream
        .set_nonblocking(true)
        .expect("set fake upstream nonblocking");
    let upstream_port = upstream.local_addr().unwrap().port();
    let config = format!(
        r#"
listen_addrs_ipv4 = ["127.0.0.1"]
[[zones]]
zone = "example.test"
zone_type = "External"
[zones.stores]
type = "forward"
[[zones.stores.name_servers]]
ip = "127.0.0.1"
trust_negative_responses = false
connections = [{{ port = {upstream_port}, protocol = {{ type = "tcp" }} }}]
[zones.stores.options]
timeout = 1
"#
    );
    let server = TestServer::start_temporary(&config, &[]);
    let dns_port = server.ports.get_v4(Protocol::Tcp).expect("TCP listener");

    let provider = TokioRuntimeProvider::new();
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, dns_port));
    let (stream_future, sender) = TcpClientStream::new(addr, None, None, provider);
    let stream = stream_future.await.expect("connect to test DNS server");
    let (mut client, background) = Client::<TokioRuntimeProvider>::new(stream, sender);
    tokio::spawn(background);
    let response = query_message(
        &mut client,
        Name::from_str("example.test.").unwrap(),
        RecordType::AXFR,
    )
    .await
    .expect("AXFR query must receive a DNS response");
    assert_eq!(response.response_code(), ResponseCode::Refused);
    assert!(
        matches!(upstream.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
        "AXFR must be refused locally without contacting the forwarder"
    );
}

#[tokio::test]
#[cfg(feature = "resolver")]
async fn test_forward() {
    use crate::server_harness::query_message;

    subscribe();
    let provider = TokioRuntimeProvider::new();
    let server = TestServer::start("example_forwarder.toml");
    let tcp_port = server.ports.get_v4(Protocol::Tcp);

    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, tcp_port.expect("no tcp_port")));
    let (future, sender) = TcpClientStream::new(addr, None, None, provider.clone());
    let stream = future.await.expect("failed to create tcp stream");

    let (mut client, bg) = Client::<TokioRuntimeProvider>::new(stream, sender);
    tokio::spawn(bg);

    let response = query_message(
        &mut client,
        Name::from_str("www.example.com.").unwrap(),
        RecordType::A,
    )
    .await
    .unwrap();

    assert!(
        response
            .answers()
            .iter()
            .any(|record| matches!(record.data(), RData::A(_)))
    );

    // just tests that multiple queries work
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, tcp_port.expect("no tcp_port")));
    let (future, sender) = TcpClientStream::new(addr, None, None, provider.clone());
    let stream = future.await.expect("failed to create tcp stream");

    let (mut client, bg) = Client::<TokioRuntimeProvider>::new(stream, sender);
    tokio::spawn(bg);

    let response = query_message(
        &mut client,
        Name::from_str("www.example.com.").unwrap(),
        RecordType::A,
    )
    .await
    .unwrap();
    assert!(
        response
            .answers()
            .iter()
            .any(|record| matches!(record.data(), RData::A(_)))
    );
    assert!(!response.header().authoritative());
}

#[tokio::test]
async fn test_allow_networks_toml_startup() {
    subscribe();
    let provider = TokioRuntimeProvider::new();
    let server = TestServer::start("example_allow_networks.toml");
    let tcp_port = server.ports.get_v4(Protocol::Tcp);

    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, tcp_port.expect("no tcp_port")));
    let (future, sender) = TcpClientStream::new(addr, None, None, provider.clone());
    let stream = future.await.expect("failed to create tcp stream");

    let (mut client, bg) = Client::<TokioRuntimeProvider>::new(stream, sender);
    tokio::spawn(bg);
    // ipv4 should succeed
    query_a(&mut client).await;

    let tcp_port = server.ports.get_v6(Protocol::Tcp);
    let addr = SocketAddr::from((Ipv6Addr::LOCALHOST, tcp_port.expect("no tcp_port")));
    let (future, sender) = TcpClientStream::new(addr, None, None, provider.clone());
    let stream = future.await.expect("failed to create tcp stream");
    let (mut client, bg) = Client::<TokioRuntimeProvider>::new(stream, sender);
    tokio::spawn(bg);

    // ipv6 should succeed
    query_a(&mut client).await;
}

#[tokio::test]
async fn test_deny_networks_toml_startup() {
    subscribe();
    let provider = TokioRuntimeProvider::new();
    let server = TestServer::start("example_deny_networks.toml");
    let tcp_port = server.ports.get_v4(Protocol::Tcp);

    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, tcp_port.expect("no tcp_port")));
    let (future, sender) = TcpClientStream::new(addr, None, None, provider.clone());
    let stream = future.await.expect("failed to create tcp stream");

    let (mut client, bg) = Client::<TokioRuntimeProvider>::new(stream, sender);
    tokio::spawn(bg);
    // ipv4 should be refused
    query_a_refused(&mut client).await;

    let tcp_port = server.ports.get_v6(Protocol::Tcp);
    let addr = SocketAddr::from((Ipv6Addr::LOCALHOST, tcp_port.expect("no tcp_port")));
    let (future, sender) = TcpClientStream::new(addr, None, None, provider.clone());
    let stream = future.await.expect("failed to create tcp stream");
    let (mut client, bg) = Client::<TokioRuntimeProvider>::new(stream, sender);
    tokio::spawn(bg);

    // ipv6 should be refused
    query_a_refused(&mut client).await;
}

#[tokio::test]
async fn test_deny_allow_networks_toml_startup() {
    subscribe();
    let provider = TokioRuntimeProvider::new();
    let server = TestServer::start("example_deny_allow_networks.toml");
    let tcp_port = server.ports.get_v4(Protocol::Tcp);

    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, tcp_port.expect("no tcp_port")));
    let (future, sender) = TcpClientStream::new(addr, None, None, provider.clone());
    let stream = future.await.expect("failed to create tcp stream");

    let (mut client, bg) = Client::<TokioRuntimeProvider>::new(stream, sender);
    tokio::spawn(bg);
    // ipv4 should succeed
    query_a(&mut client).await;

    let tcp_port = server.ports.get_v6(Protocol::Tcp);
    let addr = SocketAddr::from((Ipv6Addr::LOCALHOST, tcp_port.expect("no tcp_port")));
    let (future, sender) = TcpClientStream::new(addr, None, None, provider.clone());
    let stream = future.await.expect("failed to create tcp stream");
    let (mut client, bg) = Client::<TokioRuntimeProvider>::new(stream, sender);
    tokio::spawn(bg);

    // ipv6 should be refused
    query_a_refused(&mut client).await;
}
