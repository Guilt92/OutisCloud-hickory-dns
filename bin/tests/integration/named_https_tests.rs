// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![cfg(not(windows))]
#![cfg(feature = "__https")]

use std::env;
use std::fs::File;
use std::io::*;
use std::net::*;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, RootCertStore};

use crate::server_harness::{TestServer, query_a};
use hickory_net::client::{Client, ClientHandle};
use hickory_net::h2::HttpsClientStream;
use hickory_net::runtime::TokioRuntimeProvider;
use hickory_net::tls::default_provider;
use hickory_net::xfer::Protocol;
use test_support::subscribe;

#[tokio::test]
async fn test_example_https_toml_startup() {
    subscribe();

    const ALPN_H2: &[u8] = b"h2";

    let server = TestServer::start("dns_over_https.toml");
    let mut cert_der = vec![];
    let https_port = server.ports.get_v4(Protocol::Https);
    let server_path = env::var("TDNS_WORKSPACE_ROOT").unwrap_or_else(|_| "..".to_owned());
    println!("using server src path: {server_path}");

    File::open(format!(
        "{server_path}/tests/test-data/test_configs/sec/example.cert"
    ))
    .expect("failed to open cert")
    .read_to_end(&mut cert_der)
    .expect("failed to read cert");

    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, https_port.expect("no https_port")));
    std::thread::sleep(std::time::Duration::from_secs(1));

    // using the mozilla default root store
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    root_store.add(CertificateDer::from(cert_der)).unwrap();

    let mut client_config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    client_config.alpn_protocols.push(ALPN_H2.to_vec());

    let client_config = Arc::new(client_config);
    let provider = TokioRuntimeProvider::new();
    let sender = HttpsClientStream::builder(client_config, provider)
        .build(addr, Arc::from("ns.example.com"), Arc::from("/dns-query"))
        .await
        .unwrap();
    let (mut client, bg) = Client::<TokioRuntimeProvider>::from_sender(sender);
    tokio::spawn(bg);

    // ipv4 should succeed
    query_a(&mut client).await;

    // a second request should work...
    query_a(&mut client).await;
}

#[tokio::test]
async fn https_h2_fanout_is_bounded_and_service_recovers() {
    use hickory_proto::rr::{DNSClass, Name, RecordType};
    use std::str::FromStr;

    let zone = "$ORIGIN example.test.\n@ 300 IN SOA ns.example.test. hostmaster.example.test. 1 3600 600 604800 300\n@ 300 IN NS ns.example.test.\nns 300 IN A 192.0.2.1\nwww 300 IN A 192.0.2.42\n";
    let config = r#"
listen_addrs_ipv4 = ["127.0.0.1"]

[tls_cert]
path = "server.cert.pem"
private_key = "server.key.pem"
endpoint_name = "localhost"

[[zones]]
zone = "example.test"
zone_type = "Primary"
file = "example.test.zone"
"#;
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
        .expect("generate test HTTPS certificate");
    let cert_pem = certificate.cert.pem();
    let key_pem = certificate.key_pair.serialize_pem();
    let server = TestServer::start_temporary_with_env(
        config,
        &[
            ("example.test.zone", zone),
            ("server.cert.pem", &cert_pem),
            ("server.key.pem", &key_pem),
        ],
        &[
            ("DNS_MAX_TCP_CONNECTIONS", "8"),
            ("DNS_MAX_H2_STREAMS", "2"),
        ],
    );

    let mut roots = RootCertStore::empty();
    roots
        .add(certificate.cert.der().clone())
        .expect("trust isolated HTTPS server cert");
    let client_config = Arc::new(
        ClientConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()
            .expect("configure supported TLS versions")
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let addr = SocketAddr::from((
        Ipv4Addr::LOCALHOST,
        server.ports.get_v4(Protocol::Https).unwrap(),
    ));
    let provider = TokioRuntimeProvider::new();
    let sender = HttpsClientStream::builder(client_config.clone(), provider.clone())
        .build(addr, Arc::from("localhost"), Arc::from("/dns-query"))
        .await
        .expect("establish seed HTTP/2 connection");
    let (client, background) = Client::<TokioRuntimeProvider>::from_sender(sender);
    let background = tokio::spawn(background);

    // All requests are released together on one HTTP/2 connection. Requests beyond
    // DNS_MAX_H2_STREAMS are refused/reset while admitted streams complete normally.
    let barrier = Arc::new(tokio::sync::Barrier::new(65));
    let mut requests = Vec::new();
    for _ in 0..64 {
        let mut client = client.clone();
        let barrier = barrier.clone();
        requests.push(tokio::spawn(async move {
            barrier.wait().await;
            tokio::time::timeout(
                Duration::from_secs(2),
                client.query(
                    Name::from_str("www.example.test.").unwrap(),
                    DNSClass::IN,
                    RecordType::A,
                ),
            )
            .await
            .is_ok_and(|response| response.is_ok_and(|response| !response.answers().is_empty()))
        }));
    }
    barrier.wait().await;
    let mut successes = 0;
    for request in requests {
        successes += usize::from(request.await.expect("join H2 query task"));
    }
    assert!(successes > 0, "the H2 admission cap rejected every request");
    assert!(
        successes < 64,
        "the H2 stream cap did not apply under fanout"
    );
    background.abort();
    drop(client);

    // Fan out independent TLS connections beyond the TCP admission cap too.
    let mut connections = Vec::new();
    for _ in 0..24 {
        let config = client_config.clone();
        let provider = TokioRuntimeProvider::new();
        connections.push(tokio::spawn(async move {
            let Ok(Ok(sender)) = tokio::time::timeout(
                Duration::from_secs(3),
                HttpsClientStream::builder(config, provider).build(
                    addr,
                    Arc::from("localhost"),
                    Arc::from("/dns-query"),
                ),
            )
            .await
            else {
                return false;
            };
            let (mut client, background) = Client::<TokioRuntimeProvider>::from_sender(sender);
            let background = tokio::spawn(background);
            let success = tokio::time::timeout(
                Duration::from_secs(3),
                client.query(
                    Name::from_str("www.example.test.").unwrap(),
                    DNSClass::IN,
                    RecordType::A,
                ),
            )
            .await
            .is_ok_and(|response| response.is_ok_and(|response| !response.answers().is_empty()));
            background.abort();
            success
        }));
    }
    let mut connection_successes = 0;
    for connection in connections {
        connection_successes += usize::from(connection.await.expect("join TLS connection test"));
    }
    assert!(
        connection_successes > 0,
        "all TLS connections were rejected"
    );
    assert!(
        connection_successes < 24,
        "TCP connection admission did not limit TLS fanout"
    );

    let sender = HttpsClientStream::builder(client_config, TokioRuntimeProvider::new())
        .build(addr, Arc::from("localhost"), Arc::from("/dns-query"))
        .await
        .expect("establish HTTPS connection after fanout");
    let (mut client, background) = Client::<TokioRuntimeProvider>::from_sender(sender);
    let background = tokio::spawn(background);
    let response = tokio::time::timeout(
        Duration::from_secs(3),
        client.query(
            Name::from_str("www.example.test.").unwrap(),
            DNSClass::IN,
            RecordType::A,
        ),
    )
    .await
    .expect("server recovers after HTTPS/H2 fanout")
    .expect("authoritative query succeeds after fanout");
    assert!(!response.answers().is_empty());
    background.abort();
}
