#![allow(unreachable_pub)]

use std::{
    collections::{HashMap, VecDeque},
    env, fs,
    io::{BufRead, BufReader},
    net::SocketAddr,
    path::PathBuf,
    process::{Child, Command, Stdio},
    str::FromStr,
    sync::{Arc, Mutex},
    thread,
    time::*,
};

use regex::Regex;
use tracing::warn;

use hickory_net::{NetError, client::ClientHandle, xfer::Protocol};
#[cfg(feature = "__dnssec")]
use hickory_net::{client::Client, runtime::TokioRuntimeProvider, xfer::DnsHandle};
#[cfg(feature = "__dnssec")]
use hickory_proto::{
    dnssec::Algorithm,
    op::{DnsRequest, Edns},
};
use hickory_proto::{
    op::{DnsResponse, ResponseCode},
    rr::{DNSClass, Name, RData, RecordType, rdata::A},
};
#[cfg(feature = "__dnssec")]
use hickory_server::zone_handler::LookupOptions;

#[derive(Debug, Default)]
struct SocketPort {
    v4: u16,
    v6: u16,
}

#[derive(Debug, Default)]
pub struct SocketPorts(HashMap<ServerProtocol, SocketPort>);

impl SocketPorts {
    /// This will overwrite the existing value
    fn put(&mut self, protocol: impl Into<ServerProtocol>, addr: SocketAddr) {
        let entry = self.0.entry(protocol.into()).or_default();

        if addr.is_ipv4() {
            entry.v4 = addr.port();
        } else {
            entry.v6 = addr.port();
        }
    }

    /// Assumes there is only one V4 addr for the IP based on the usage in the Server
    pub fn get_v4(&self, protocol: impl Into<ServerProtocol>) -> Option<u16> {
        self.0
            .get(&protocol.into())
            .iter()
            .find_map(|ports| if ports.v4 == 0 { None } else { Some(ports.v4) })
    }

    /// Assumes there is only one V4 addr for the IP based on the usage in the Server
    pub fn get_v6(&self, protocol: impl Into<ServerProtocol>) -> Option<u16> {
        self.0
            .get(&protocol.into())
            .iter()
            .find_map(|ports| if ports.v6 == 0 { None } else { Some(ports.v6) })
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ServerProtocol {
    Dns(Protocol),
    #[cfg(feature = "metrics")]
    PrometheusMetrics,
}

impl From<Protocol> for ServerProtocol {
    fn from(proto: Protocol) -> Self {
        Self::Dns(proto)
    }
}

fn collect_and_print<R: BufRead>(read: &mut R, output: &mut String) {
    output.clear();
    read.read_line(output).expect("could not read stdio");

    if !output.is_empty() {
        // uncomment for debugging
        // println!("SRV: {}", output.trim_end());
    }
}

pub struct TestServer {
    pub ports: SocketPorts,
    child: Child,
    output: Arc<Mutex<VecDeque<String>>>,
    output_reader: Option<thread::JoinHandle<()>>,
    _temp_dir: Option<tempfile::TempDir>,
}

impl TestServer {
    /// Spins up a Server and handles shutting it down after running the test
    #[allow(dead_code)]
    pub fn start(toml: &str) -> Self {
        let server_path = env::var("TDNS_WORKSPACE_ROOT").unwrap_or_else(|_| "..".to_owned());
        println!("using server src path: {server_path}");

        Self::start_from_paths(
            PathBuf::from(format!("{server_path}/tests/test-data/test_configs/{toml}")),
            PathBuf::from(format!("{server_path}/tests/test-data/test_configs")),
            None,
            &[],
        )
    }

    /// Starts a checked-in test server config with isolated process environment overrides.
    pub fn start_with_env(toml: &str, child_env: &[(&str, &str)]) -> Self {
        let server_path = env::var("TDNS_WORKSPACE_ROOT").unwrap_or_else(|_| "..".to_owned());
        Self::start_from_paths(
            PathBuf::from(format!("{server_path}/tests/test-data/test_configs/{toml}")),
            PathBuf::from(format!("{server_path}/tests/test-data/test_configs")),
            None,
            child_env,
        )
    }

    /// Start an isolated server with fixtures written to a temporary directory.
    /// The directory remains alive until the child server is dropped.
    pub fn start_temporary(config: &str, files: &[(&str, &str)]) -> Self {
        Self::start_temporary_with_env(config, files, &[])
    }

    /// Starts an isolated server with fixture files and process environment overrides.
    pub fn start_temporary_with_env(
        config: &str,
        files: &[(&str, &str)],
        child_env: &[(&str, &str)],
    ) -> Self {
        Self::start_temporary_inner(config, files, child_env, false)
    }

    /// Starts a temporary server whose zone directory can be atomically
    /// replaced by a dropped-privilege child process. Permissions are set
    /// before startup so both the zone watcher and transfer writer can access
    /// the fixture directory.
    pub fn start_temporary_with_zone_writes(config: &str, files: &[(&str, &str)]) -> Self {
        Self::start_temporary_inner(config, files, &[], true)
    }

    fn start_temporary_inner(
        config: &str,
        files: &[(&str, &str)],
        child_env: &[(&str, &str)],
        allow_zone_writes: bool,
    ) -> Self {
        let temp_dir = tempfile::tempdir().expect("create temporary DNS config directory");
        for (name, contents) in files {
            let path = temp_dir.path().join(name);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("create temporary fixture parent");
            }
            fs::write(path, contents).expect("write temporary DNS fixture");
        }
        let config_path = temp_dir.path().join("named.toml");
        fs::write(&config_path, config).expect("write temporary named config");
        #[cfg(unix)]
        if allow_zone_writes {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(temp_dir.path(), fs::Permissions::from_mode(0o777))
                .expect("allow isolated child to update its test zone files before startup");
        }
        #[cfg(not(unix))]
        let _ = allow_zone_writes;
        Self::start_from_paths(
            config_path,
            temp_dir.path().to_path_buf(),
            Some(temp_dir),
            child_env,
        )
    }

    /// Replace a fixture in a temporary server directory to exercise reload behavior.
    pub fn write_temporary_file(&self, name: &str, contents: &str) {
        let temp_dir = self
            ._temp_dir
            .as_ref()
            .expect("temporary files are only available for temporary servers");
        let path = temp_dir.path().join(name);
        fs::write(path, contents).expect("write temporary server fixture");
    }

    /// Read a fixture after the child server has exercised file-backed behavior.
    pub fn read_temporary_file(&self, name: &str) -> String {
        let temp_dir = self
            ._temp_dir
            .as_ref()
            .expect("temporary files are only available for temporary servers");
        fs::read_to_string(temp_dir.path().join(name)).expect("read temporary server fixture")
    }

    /// Stop this isolated server while keeping the fixture directory alive.
    pub fn stop(&mut self) {
        if let Err(err) = self.child.kill() {
            if err.kind() != std::io::ErrorKind::InvalidInput {
                warn!("could not kill test server: {err}");
            }
        }
        if let Err(err) = self.child.wait() {
            warn!("could not wait for test server: {err}");
        }
        if let Some(reader) = self.output_reader.take() {
            if reader.join().is_err() {
                warn!("test server output reader panicked");
            }
        }
    }

    /// Permit the isolated child server's dropped-privilege account to atomically
    /// replace zone fixtures, as a real secondary must do after a valid AXFR.
    #[cfg(unix)]
    pub fn allow_child_zone_file_replacement(&self) {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = self
            ._temp_dir
            .as_ref()
            .expect("temporary files are only available for temporary servers");
        fs::set_permissions(temp_dir.path(), fs::Permissions::from_mode(0o777))
            .expect("allow the isolated child to replace zone files");
    }

    fn start_from_paths(
        config_path: PathBuf,
        zone_dir: PathBuf,
        temp_dir: Option<tempfile::TempDir>,
        child_env: &[(&str, &str)],
    ) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_hickory-dns"));
        command
        .stdout(Stdio::piped())
        .env(
            "RUST_LOG",
            "hickory_dns=debug,hickory_client=debug,hickory_proto=debug,hickory_resolver=debug,hickory_server=debug",
        )
        .envs(child_env.iter().copied())
        .arg("-d")
        .arg(format!("--config={}", config_path.display()))
        .arg(format!("--zonedir={}", zone_dir.display()))
        .arg(format!("--port={}", 0));
        #[cfg(feature = "__tls")]
        command.arg(format!("--tls-port={}", 0));
        #[cfg(feature = "__https")]
        command.arg(format!("--https-port={}", 0));
        #[cfg(feature = "__quic")]
        command.arg(format!("--quic-port={}", 0));
        #[cfg(feature = "__h3")]
        command.arg(format!("--h3-port={}", 0));
        #[cfg(feature = "prometheus-metrics")]
        command.arg(format!("--prometheus-listen-address=127.0.0.1:{}", 0));

        println!("named cli options: {command:#?}");

        let mut named = command.spawn().expect("failed to start named");

        println!("server starting");

        let mut stdout = BufReader::new(named.stdout.take().expect("no stdout"));

        // These will be collected from the server startup output
        let mut ports = SocketPorts::default();

        let mut output = String::new();
        let mut found = false;
        let wait_for_start_until = Instant::now() + Duration::from_secs(60);

        // Search strings for the ports used during testing
        let addr_regex = Regex::new(
            r"listening for (UDP|TCP|TLS|HTTPS|QUIC|H3|HTTP/3|Prometheus metrics) on ((?:(?:0\.0\.0\.0)|(?:127\.0\.0\.1)|(?:\[::\])):\d+)",
        )
        .unwrap();

        while Instant::now() < wait_for_start_until {
            if let Some(ret_code) = named.try_wait().expect("failed to check status of named") {
                panic!("named has already exited with code: {ret_code}");
            }

            collect_and_print(&mut stdout, &mut output);

            if let Some(addr) = addr_regex.captures(&output) {
                let proto = addr.get(1).expect("missing protocol").as_str();
                let socket_addr = addr.get(2).expect("missing socket addr").as_str();

                let socket_addr =
                    SocketAddr::from_str(socket_addr).expect("could not parse socket_addr");

                match proto {
                    "UDP" => ports.put(Protocol::Udp, socket_addr),
                    "TCP" => ports.put(Protocol::Tcp, socket_addr),
                    #[cfg(feature = "__tls")]
                    "TLS" => ports.put(Protocol::Tls, socket_addr),
                    #[cfg(feature = "__https")]
                    "HTTPS" => ports.put(Protocol::Https, socket_addr),
                    #[cfg(feature = "__quic")]
                    "QUIC" => ports.put(Protocol::Quic, socket_addr),
                    #[cfg(feature = "__h3")]
                    "H3" | "HTTP/3" => ports.put(Protocol::H3, socket_addr),
                    #[cfg(feature = "metrics")]
                    "Prometheus metrics" => {
                        ports.put(ServerProtocol::PrometheusMetrics, socket_addr)
                    }
                    _ => panic!("unsupported protocol: {proto}"),
                }
            } else if output.contains("awaiting connections...") {
                found = true;
                break;
            }
        }

        assert!(found);
        println!("Test server started. ports: {ports:?}");

        // Drain child output continuously. Leaving the captured pipe unread until Drop
        // deadlocks the DNS process under query-load tests once its pipe buffer fills.
        let output = Arc::new(Mutex::new(VecDeque::with_capacity(2048)));
        let output_for_reader = output.clone();
        let output_reader = thread::spawn(move || {
            for line in stdout.lines() {
                let Ok(line) = line else { break };
                let mut recent = output_for_reader.lock().expect("test server output mutex");
                if recent.len() == 256 {
                    recent.pop_front();
                }
                recent.push_back(line);
            }
        });

        Self {
            ports,
            child: named,
            output,
            output_reader: Some(output_reader),
            _temp_dir: temp_dir,
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.stop();
        if let Ok(output) = self.output.lock() {
            for line in output.iter() {
                println!("SRV: {line}");
            }
        }
    }
}

pub async fn query_message<C: ClientHandle>(
    client: &mut C,
    name: Name,
    record_type: RecordType,
) -> Result<DnsResponse, NetError> {
    println!("sending request: {name} for: {record_type}");
    client.query(name, DNSClass::IN, record_type).await
}

// This only validates that a query to the server works, it shouldn't be used for more than this.
//  i.e. more complex checks live with the clients and zone handlers to validate deeper functionality
pub async fn query_a<C: ClientHandle>(client: &mut C) {
    let name = Name::from_str("www.example.com.").unwrap();
    let response = query_message(client, name, RecordType::A).await.unwrap();
    let record = &response.answers()[0];

    if let RData::A(address) = record.data() {
        assert_eq!(address, &A::new(127, 0, 0, 1))
    } else {
        panic!("wrong RDATA")
    }
}

// This only validates that a query to the server works, it shouldn't be used for more than this.
//  i.e. more complex checks live with the clients and zone handlers to validate deeper functionality
pub async fn query_a_refused<C: ClientHandle>(client: &mut C) {
    let name = Name::from_str("www.example.com.").unwrap();
    let response = query_message(client, name, RecordType::A).await.unwrap();

    assert_eq!(response.response_code(), ResponseCode::Refused);
}

// This only validates that a query to the server works, it shouldn't be used for more than this.
//  i.e. more complex checks live with the clients and zone handlers to validate deeper functionality
#[cfg(feature = "__dnssec")]
pub async fn query_all_dnssec(client: Client<TokioRuntimeProvider>, algorithm: Algorithm) {
    use hickory_proto::{
        dnssec::{
            PublicKey,
            rdata::{DNSKEY, RRSIG},
        },
        rr::{Record, RecordData},
    };

    let name = Name::from_str("example.com.").unwrap();
    let mut client = MutMessageHandle::new(client);
    client.lookup_options.dnssec_ok = true;

    let response = query_message(&mut client, name.clone(), RecordType::DNSKEY)
        .await
        .unwrap();

    let dnskey = response
        .answers()
        .iter()
        .map(Record::data)
        .filter_map(DNSKEY::try_borrow)
        .find(|d| d.public_key().algorithm() == algorithm);
    assert!(dnskey.is_some(), "DNSKEY not found");

    let response = query_message(&mut client, name, RecordType::DNSKEY)
        .await
        .unwrap();

    let rrsig = response
        .answers()
        .iter()
        .map(Record::data)
        .filter_map(RRSIG::try_borrow)
        .filter(|rrsig| rrsig.input().algorithm == algorithm)
        .find(|rrsig| rrsig.input().type_covered == RecordType::DNSKEY);
    assert!(rrsig.is_some(), "Associated RRSIG not found");
}

#[cfg(feature = "__dnssec")]
#[derive(Clone)]
pub struct MutMessageHandle<C: ClientHandle + Unpin> {
    client: C,
    pub lookup_options: LookupOptions,
}

#[cfg(feature = "__dnssec")]
impl<C: ClientHandle + Unpin> MutMessageHandle<C> {
    pub fn new(client: C) -> Self {
        Self {
            client,
            #[cfg(feature = "__dnssec")]
            lookup_options: LookupOptions::default(),
        }
    }
}

#[cfg(feature = "__dnssec")]
impl<C: ClientHandle + Unpin> DnsHandle for MutMessageHandle<C> {
    type Response = <C as DnsHandle>::Response;
    type Runtime = C::Runtime;

    fn is_verifying_dnssec(&self) -> bool {
        true
    }

    fn send(&self, mut request: DnsRequest) -> Self::Response {
        // mutable block
        let edns = request.extensions_mut().get_or_insert_with(Edns::new);
        edns.set_dnssec_ok(true);

        println!("sending message");
        self.client.send(request)
    }
}
