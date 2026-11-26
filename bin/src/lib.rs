#[cfg(any(
    feature = "__tls",
    feature = "__https",
    feature = "__quic",
    feature = "__h3"
))]
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use std::{
    io::Error,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
};

use clap::Parser;
#[cfg(feature = "metrics")]
use metrics_process::Collector;
#[cfg(any(
    feature = "__tls",
    feature = "__https",
    feature = "__quic",
    feature = "__h3"
))]
use rustls::KeyLogFile;
#[cfg(any(
    feature = "__tls",
    feature = "__https",
    feature = "__quic",
    feature = "__h3"
))]
use rustls::server::ResolvesServerCert;
use socket2::{Domain, Socket, Type};
use tokio::net::{TcpListener, UdpSocket};
#[cfg(unix)]
use tokio::signal::unix::{SignalKind, signal};
#[cfg(feature = "metrics")]
use tokio::time::sleep;
#[cfg(any(
    feature = "__tls",
    feature = "__https",
    feature = "__quic",
    feature = "__h3"
))]
use tracing::warn;
use tracing::{error, info, warn};

use futures_util::StreamExt;
#[cfg(feature = "__dnssec")]
use hickory_net::DnsMultiplexer;
use hickory_net::{
    client::{Client, ClientHandle},
    runtime::TokioRuntimeProvider,
    tcp::TcpClientStream,
};
use hickory_server::proto::ProtoError;
use hickory_server::proto::rr::{
    DNSClass, Name, RData, Record, RecordSet, RecordType, rdata::opt::NSIDPayload,
};
use hickory_server::proto::serialize::txt::Parser as ZoneParser;
#[cfg(feature = "__tls")]
use hickory_server::server::default_tls_server_config;
use hickory_server::{
    server::Server,
    zone_handler::{
        Catalog,
        swap::{RateLimitConfig, SwapHandler},
    },
};

mod config;
#[cfg(feature = "prometheus-metrics")]
use ::metrics::{counter, describe_counter};
use config::{Config, NotifyPeerConfig, ServerStoreConfig, ZoneConfig, ZoneTypeConfig};
use notify::{Config as NotifyConfig, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::sync::Arc as SyncArc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration as StdDuration;
use uuid::Uuid;

#[cfg(feature = "__dnssec")]
pub mod dnssec;

#[cfg(feature = "metrics")]
pub mod metrics;
#[cfg(feature = "metrics")]
use crate::metrics::ConfigMetrics;

#[cfg(feature = "prometheus-metrics")]
mod prometheus_server;
#[cfg(feature = "prometheus-metrics")]
use prometheus_server::PrometheusServer;
#[cfg(feature = "prometheus-metrics")]
mod readiness;
#[cfg(feature = "prometheus-metrics")]
use readiness::Readiness;

/// Cli struct for all options managed with clap derive api.
#[derive(Debug, Parser)]
#[clap(name = "Hickory DNS named server", version, about)]
pub struct DnsServer {
    /// Test validation of configuration files
    #[clap(long = "validate")]
    validate: bool,

    /// Number of runtime workers, defaults to the number of CPU cores
    #[clap(long = "workers")]
    pub workers: Option<usize>,

    /// Disable INFO messages, WARN and ERROR will remain
    #[clap(short = 'q', long = "quiet", conflicts_with = "debug")]
    pub quiet: bool,

    /// Turn on `DEBUG` messages (default is only `INFO`)
    #[clap(short = 'd', long = "debug", conflicts_with = "quiet")]
    pub debug: bool,

    /// Path to configuration file of named server
    #[clap(
        short = 'c',
        long = "config",
        default_value = "/etc/hickory/named.toml",
        value_name = "NAME",
        value_hint=clap::ValueHint::FilePath,
    )]
    config: PathBuf,

    /// Path to the root directory for all zone files,
    /// see also config toml
    #[clap(short = 'z', long = "zonedir", value_name = "DIR", value_hint=clap::ValueHint::DirPath)]
    zonedir: Option<PathBuf>,

    /// Listening port for DNS queries,
    /// overrides any value in config file
    #[clap(short = 'p', long = "port", value_name = "PORT")]
    port: Option<u16>,

    /// Listening port for DNS over TLS queries,
    /// overrides any value in config file
    #[cfg(feature = "__tls")]
    #[clap(long = "tls-port", value_name = "TLS-PORT")]
    tls_port: Option<u16>,

    /// Listening port for DNS over HTTPS queries,
    /// overrides any value in config file
    #[cfg(feature = "__https")]
    #[clap(long = "https-port", value_name = "HTTPS-PORT")]
    https_port: Option<u16>,

    /// Listening port for DNS over QUIC queries,
    /// overrides any value in config file
    #[cfg(feature = "__quic")]
    #[clap(long = "quic-port", value_name = "QUIC-PORT")]
    quic_port: Option<u16>,

    /// Listening port for DNS over HTTP/3 queries,
    /// overrides any value in config file
    #[cfg(feature = "__h3")]
    #[clap(long = "h3-port", value_name = "H3-PORT")]
    h3_port: Option<u16>,

    /// Listening socket for Prometheus metrics,
    /// for remote access configure socket as needed (e.g. 0.0.0.0:9000)
    /// overrides any value in config file
    #[cfg(feature = "prometheus-metrics")]
    #[clap(
        long = "prometheus-listen-address",
        value_name = "PROMETHEUS-LISTEN-ADDRESS"
    )]
    prometheus_listen_addr: Option<SocketAddr>,

    /// Disable TCP protocol,
    /// overrides any value in config file
    #[clap(long = "disable-tcp")]
    disable_tcp: bool,

    /// Disable UDP protocol,
    /// overrides any value in config file
    #[clap(long = "disable-udp")]
    disable_udp: bool,

    /// Disable TLS protocol,
    /// overrides any value in config file
    #[cfg(feature = "__tls")]
    #[clap(long = "disable-tls", conflicts_with = "tls_port")]
    disable_tls: bool,

    /// Disable HTTPS protocol,
    /// overrides any value in config file
    #[cfg(feature = "__https")]
    #[clap(long = "disable-https", conflicts_with = "https_port")]
    disable_https: bool,

    /// Disable QUIC protocol,
    /// overrides any value in config file
    #[cfg(feature = "__quic")]
    #[clap(long = "disable-quic", conflicts_with = "quic_port")]
    disable_quic: bool,

    /// Disable HTTP/3 protocol,
    /// overrides any value in config file
    #[cfg(feature = "__h3")]
    #[clap(long = "disable-h3", conflicts_with = "h3_port")]
    disable_h3: bool,

    /// Disable Prometheus metrics,
    /// overrides any value in config file
    #[cfg(feature = "prometheus-metrics")]
    #[clap(long = "disable-prometheus", conflicts_with = "prometheus_listen_addr")]
    disable_prometheus: bool,

    /// Name server identifier (NSID) payload for EDNS responses.
    /// Use `0x` prefix for hex-encoded data. Mutually exclusive with --nsid-hostname
    #[clap(long = "nsid", value_name = "NSID", conflicts_with = "nsid_hostname", value_parser = parse_nsid_payload)]
    nsid: Option<NSIDPayload>,

    /// Use the system hostname as the name server identifier (NSID) payload
    /// for EDNS responses.
    /// Mutually exclusive with --nsid
    #[clap(long = "nsid-hostname", conflicts_with = "nsid")]
    nsid_hostname: bool,
}

impl DnsServer {
    pub async fn run(self) -> Result<(), String> {
        let Self {
            validate,
            workers: _, // Used in `main()`
            quiet: _,   // Used in `main()`
            debug: _,   // Used in `main()`
            config,
            zonedir,
            port,
            #[cfg(feature = "__tls")]
            tls_port,
            #[cfg(feature = "__https")]
            https_port,
            #[cfg(feature = "__quic")]
            quic_port,
            #[cfg(feature = "__h3")]
            h3_port,
            #[cfg(feature = "prometheus-metrics")]
            prometheus_listen_addr,
            disable_tcp,
            disable_udp,
            #[cfg(feature = "__tls")]
            disable_tls,
            #[cfg(feature = "__https")]
            disable_https,
            #[cfg(feature = "__quic")]
            disable_quic,
            #[cfg(feature = "__h3")]
            disable_h3,
            #[cfg(feature = "prometheus-metrics")]
            disable_prometheus,
            nsid,
            nsid_hostname,
        } = self;

        let config_path = Path::new(&config);
        info!("loading configuration from: {config_path:?}");
        let mut config = Config::read_config(config_path)
            .map_err(|err| format!("failed to read config file from {config_path:?}: {err}"))?;
        // Everything except the zone list needs a process restart to change
        // (sockets, TLS, privileges); zones are reloaded in place.
        let startup_fingerprint = listener_fingerprint(&mut config);
        let zonedir_for_reload = zonedir.clone();

        #[cfg(feature = "prometheus-metrics")]
        let disable_prometheus = disable_prometheus | config.disable_prometheus;
        #[cfg(feature = "prometheus-metrics")]
        let readiness = Readiness::new();
        let disable_udp = disable_udp | config.disable_udp;
        let disable_tcp = disable_tcp | config.disable_tcp;
        #[cfg(feature = "__tls")]
        let disable_tls = disable_tls | config.disable_tls;
        #[cfg(feature = "__https")]
        let disable_https = disable_https | config.disable_https;
        #[cfg(feature = "__quic")]
        let disable_quic = disable_quic | config.disable_quic;
        #[cfg(feature = "__h3")]
        let disable_h3 = disable_h3 | config.disable_h3;

        #[cfg(feature = "prometheus-metrics")]
        let prometheus_server_opt = if !disable_prometheus {
            let socket_addr = prometheus_listen_addr.unwrap_or_else(|| {
                config
                    .prometheus_listen_addr
                    .unwrap_or_else(|| SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 9000))
            });
            let listener =
                build_tcp_listener(socket_addr.ip(), socket_addr.port()).map_err(|err| {
                    format!(
                        "failed to bind to Prometheus TCP socket address {socket_addr:?}: {err}"
                    )
                })?;
            let local_addr = listener
                .local_addr()
                .map_err(|err| format!("failed to look up local address: {err}"))?;

            // Set up Prometheus HTTP server.
            let metrics_token = std::env::var("PROMETHEUS_TOKEN")
                .or_else(|_| std::env::var("METRICS_TOKEN"))
                .ok()
                .filter(|token| !token.is_empty());
            let server = PrometheusServer::new(listener, readiness.clone(), metrics_token)?;
            info!("listening for Prometheus metrics on {local_addr:?}");
            Some(server)
        } else {
            info!("Prometheus metrics are disabled");
            None
        };

        #[cfg(feature = "metrics")]
        let (process_metrics_collector, config_metrics) = {
            // setup process metrics (cpu, memory, ...) collection
            let collector = Collector::default();
            collector.describe(); // add metric descriptions

            let process_metrics_collector = tokio::spawn(async move {
                loop {
                    sleep(Duration::from_secs(1)).await;
                    collector.collect();
                }
            });

            // metrics need to be created after the recorder is registered
            // calling increment() after registration is not sufficient
            let config_metrics = ConfigMetrics::new(&config);
            (process_metrics_collector, config_metrics)
        };

        let Config {
            listen_addrs_ipv4,
            listen_addrs_ipv6,
            listen_port,
            #[cfg(feature = "__tls")]
            tls_listen_port,
            #[cfg(feature = "__https")]
            https_listen_port,
            #[cfg(feature = "__quic")]
            quic_listen_port,
            #[cfg(feature = "__h3")]
            h3_listen_port,
            #[cfg(feature = "prometheus-metrics")]
                prometheus_listen_addr: _,
            disable_tcp: _,
            disable_udp: _,
            #[cfg(feature = "__tls")]
                disable_tls: _,
            #[cfg(feature = "__https")]
                disable_https: _,
            #[cfg(feature = "__quic")]
                disable_quic: _,
            #[cfg(feature = "__h3")]
                disable_h3: _,
            #[cfg(feature = "prometheus-metrics")]
                disable_prometheus: _,
            tcp_request_timeout,
            #[cfg(feature = "__tls")]
            ssl_keylog_enabled,
            directory,
            user,
            group,
            zones,
            #[cfg(feature = "__tls")]
            tls_cert,
            #[cfg(feature = "__https")]
            http_endpoint,
            deny_networks,
            allow_networks,
        } = config;

        #[cfg(unix)]
        let mut signal = signal(SignalKind::terminate())
            .map_err(|e| format!("failed to register signal handler: {e}"))?;

        // exit flag to distinguish SIGTERM (exit) from file-change reloads
        let exit_flag = SyncArc::new(AtomicBool::new(false));

        let (notify_refresh_tx, mut notify_refresh_rx) = tokio::sync::mpsc::unbounded_channel();
        let (reload_tx, mut reload_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
        let mut catalog = Catalog::new();
        catalog.set_notify_refresh_tx(notify_refresh_tx);
        let mut zone_fingerprints = HashMap::new();
        let mut nsid_final = nsid;
        if nsid_hostname {
            let hostname =
                hostname::get().map_err(|e| format!("failed to get system hostname: {e}"))?;
            let payload = NSIDPayload::new(hostname.into_encoded_bytes())
                .map_err(|e| format!("invalid NSID payload: {e}"))?;
            nsid_final = Some(payload);
        }
        catalog.set_nsid(nsid_final.clone());

        // configure our server based on the config_path
        let zone_dir = zonedir.unwrap_or(directory);
        let mut secondary_schedules = Vec::new();
        for zone in zones {
            let zone_name = zone
                .zone()
                .map_err(|err| format!("failed to read zone name from {config_path:?}: {err}"))?;

            // A secondary must never become authoritative with an empty or
            // stale configured file when its primary can be reached. Fetch a
            // complete, validated AXFR before loading the initial catalog.
            if matches!(&zone.zone_type_config, ZoneTypeConfig::Secondary(_)) {
                let secondary_file = match &zone.zone_type_config {
                    ZoneTypeConfig::Secondary(server_config) => {
                        server_config.stores.iter().find_map(|store| match store {
                            ServerStoreConfig::File(file) => Some(file.zone_path.clone()),
                            _ => None,
                        })
                    }
                    _ => None,
                }
                .ok_or_else(|| format!("secondary zone {zone_name} has no file-backed store"))?;
                let has_valid_last_known_good = match &zone.zone_type_config {
                    ZoneTypeConfig::Secondary(_) => {
                        fs::read_to_string(zone_dir.join(&secondary_file))
                            .ok()
                            .and_then(|contents| {
                                ZoneParser::new(contents, None, Some(zone_name.clone()))
                                    .parse()
                                    .ok()
                            })
                            .is_some_and(|(_, records)| {
                                records
                                    .iter()
                                    .any(|(_, rrset)| rrset.record_type() == RecordType::SOA)
                            })
                    }
                    _ => false,
                };
                let masters = zone.masters().to_vec();
                if masters.is_empty() {
                    return Err(format!(
                        "secondary zone {zone_name} has no configured primary"
                    ));
                }
                let mut refreshed = false;
                let mut errors = Vec::new();
                for master in &masters {
                    match refresh_secondary_from_notify(
                        zone_name.clone().into(),
                        master.address,
                        &config_path,
                        &zone_dir,
                    )
                    .await
                    {
                        Ok(_) => {
                            refreshed = true;
                            break;
                        }
                        Err(error) => errors.push(error),
                    }
                }
                if !refreshed && !has_valid_last_known_good {
                    return Err(format!(
                        "secondary zone {zone_name} has no initial transfer; {}",
                        errors.join("; ")
                    ));
                }
                if !refreshed {
                    warn!(
                        %zone_name,
                        errors = %errors.join("; "),
                        "secondary initial AXFR failed; serving validated last-known-good zone"
                    );
                }
                let timers = secondary_soa_timers(&zone_name, &zone_dir.join(&secondary_file));
                secondary_schedules.push((
                    zone_name.clone().into(),
                    masters,
                    zone_dir.join(secondary_file),
                    timers,
                    refreshed,
                ));
            }

            #[cfg(feature = "metrics")]
            config_metrics.increment_zone_metrics(&zone);

            let fingerprint = zone_config_fingerprint(&zone, &zone_dir);
            match zone.load(&zone_dir).await {
                Ok(handlers) => {
                    catalog.upsert(zone_name.clone().into(), handlers);
                    if let Some(fingerprint) = fingerprint {
                        zone_fingerprints.insert(zone_name.to_string(), fingerprint);
                    }
                }
                Err(err) => return Err(format!("could not load zone {zone_name}: {err}")),
            }
        }

        if validate {
            info!("configuration files are validated");
            return Ok(());
        }

        // now, run the server, based on the config
        #[cfg_attr(not(feature = "__tls"), allow(unused_mut))]
        // Optional per-source query budget: DNS_RATE_LIMIT_QPS (0/unset = off),
        // DNS_RATE_LIMIT_BURST (default 2x QPS).
        let rate_limit = std::env::var("DNS_RATE_LIMIT_QPS")
            .ok()
            .and_then(|v| v.trim().parse::<u32>().ok())
            .filter(|q| *q > 0)
            .map(|qps| RateLimitConfig {
                queries_per_second: qps,
                burst: std::env::var("DNS_RATE_LIMIT_BURST")
                    .ok()
                    .and_then(|v| v.trim().parse::<u32>().ok())
                    .unwrap_or(qps.saturating_mul(2)),
                // DNS_RATE_LIMIT_SLIP: answer every Nth dropped UDP query with a truncated reply (default 2, 0 = never)
                slip: std::env::var("DNS_RATE_LIMIT_SLIP")
                    .ok()
                    .and_then(|v| v.trim().parse::<u32>().ok())
                    .unwrap_or(2),
            });
        if let Some(r) = &rate_limit {
            info!(
                "rate limiting: {} queries/s per source (burst {}, slip {})",
                r.queries_per_second, r.burst, r.slip
            );
        }
        let handler = SwapHandler::new(catalog, rate_limit);
        handler.set_zone_fingerprints(zone_fingerprints);
        for (zone, masters, file, timers, initial_refresh_succeeded) in secondary_schedules {
            let zone_dir = zone_dir.clone();
            let config_path = config_path.to_path_buf();
            let reload_tx = reload_tx.clone();
            let handler = handler.clone();
            tokio::spawn(async move {
                secondary_refresh_loop(
                    zone,
                    masters,
                    file,
                    timers,
                    initial_refresh_succeeded,
                    config_path,
                    zone_dir,
                    reload_tx,
                    handler,
                )
                .await;
            });
        }
        let refresh_config_path = config_path.to_path_buf();
        let refresh_zone_dir = zone_dir.clone();
        let reload_after_secondary_transfer = reload_tx.clone();
        tokio::spawn(async move {
            while let Some((zone, source)) = notify_refresh_rx.recv().await {
                match refresh_secondary_from_notify(
                    zone,
                    source,
                    &refresh_config_path,
                    &refresh_zone_dir,
                )
                .await
                {
                    Ok(true) => {
                        // File notifications are best-effort on some mounted
                        // filesystems. Explicitly reload the catalog after an
                        // installed transfer so serving state converges even
                        // when the watcher misses an atomic rename.
                        let _ = reload_after_secondary_transfer.send(());
                    }
                    Ok(false) => {}
                    Err(error) => error!(%error, "secondary zone refresh after NOTIFY failed"),
                }
            }
        });
        let mut server = Server::with_access(handler.clone(), deny_networks, allow_networks);

        let mut listen_addrs = listen_addrs_ipv4
            .into_iter()
            .map(IpAddr::V4)
            .chain(listen_addrs_ipv6.into_iter().map(IpAddr::V6))
            .collect::<Vec<_>>();

        if listen_addrs.is_empty() {
            listen_addrs.push(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
            listen_addrs.push(IpAddr::V6(Ipv6Addr::UNSPECIFIED));
        }

        let mut setup = ServerSetup {
            listen_addrs,
            server: &mut server,
            tcp_request_timeout,
            #[cfg(any(
                feature = "__tls",
                feature = "__https",
                feature = "__quic",
                feature = "__h3"
            ))]
            cert_resolver: tls_cert
                .as_ref()
                .map(|config| {
                    config.load(&zone_dir).map_err(|err| {
                        format!(
                            "failed to load TLS certificate from {:?}: {err}",
                            config.path
                        )
                    })
                })
                .transpose()?,
            #[cfg(any(
                feature = "__tls",
                feature = "__https",
                feature = "__quic",
                feature = "__h3"
            ))]
            ssl_keylog_enabled,
        };

        let listen_port = port.unwrap_or(listen_port);
        match disable_udp {
            true => info!("UDP protocol is disabled"),
            false => setup.udp(listen_port)?,
        }

        match disable_tcp {
            true => info!("TCP protocol is disabled"),
            false => setup.tcp(listen_port)?,
        }

        #[cfg(any(
            feature = "__tls",
            feature = "__https",
            feature = "__quic",
            feature = "__h3"
        ))]
        if setup.cert_resolver.is_none() {
            info!("TLS certificates are not provided");
            info!("TLS related protocols (TLS, HTTPS and QUIC) are disabled")
        }

        #[cfg(feature = "__tls")]
        match disable_tls {
            true => info!("TLS protocol is disabled"),
            false => setup.tls(tls_port.unwrap_or(tls_listen_port))?,
        }

        #[cfg(feature = "__https")]
        match disable_https {
            true => info!("HTTPS protocol is disabled"),
            false => setup.https(
                https_port.unwrap_or(https_listen_port),
                &http_endpoint,
                tls_cert
                    .as_ref()
                    .and_then(|config| config.endpoint_name.as_deref()),
            )?,
        }

        #[cfg(feature = "__quic")]
        match disable_quic {
            true => info!("QUIC protocol is disabled"),
            false => setup.quic(quic_port.unwrap_or(quic_listen_port))?,
        }

        #[cfg(feature = "__h3")]
        match disable_h3 {
            true => info!("HTTP/3 protocol is disabled"),
            false => setup.h3(h3_port.unwrap_or(h3_listen_port))?,
        }

        #[cfg(feature = "prometheus-metrics")]
        readiness.mark_ready();

        // Drop privileges on Unix systems if running as root.
        #[cfg(target_family = "unix")]
        check_drop_privs(
            user.as_deref().unwrap_or(DEFAULT_USER),
            group.as_deref().unwrap_or(&default_group()),
        )?;
        #[cfg(not(target_family = "unix"))]
        if user.is_some() || group.is_some() {
            return Err("dropping privileges is only supported on Unix systems".to_string());
        }

        #[cfg(unix)]
        {
            let token = server.shutdown_token().clone();
            let exit_flag_clone = exit_flag.clone();
            tokio::spawn(async move {
                signal.recv().await;
                // mark that this is an exit request, not just a reload
                exit_flag_clone.store(true, Ordering::SeqCst);
                token.cancel();
            });
        }

        // Watch config / zone files / GeoIP database and hot-reload the zones
        // in place. A changed listener configuration still restarts the process.
        // DNSSEC signatures are produced when a zone is loaded and are valid for 52
        // weeks. Reloading every RESIGN_INTERVAL_HOURS (default 168 = weekly, 0 = off)
        // keeps the validity window sliding so a quiet zone never serves expired
        // signatures (which would make it fail validation everywhere).
        {
            let hours: f64 = std::env::var("RESIGN_INTERVAL_HOURS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(168.0);
            let secs = (hours * 3600.0) as u64;
            if secs >= 1 {
                let tx = reload_tx.clone();
                tokio::spawn(async move {
                    let mut tick = tokio::time::interval(StdDuration::from_secs(secs));
                    tick.tick().await; // the first tick fires immediately; zones were just loaded
                    loop {
                        tick.tick().await;
                        tracing::info!("periodic reload to refresh DNSSEC signatures");
                        if tx.send(()).is_err() {
                            break;
                        }
                    }
                });
            }
        }
        let cfg_watch_path = config_path.to_path_buf();
        let zone_watch_dir = zone_dir.clone();
        let geoip_path = std::env::var_os("GEOIP_DB_PATH").map(PathBuf::from);
        std::thread::spawn(move || {
            let (tx, rx) = std::sync::mpsc::channel();
            let mut watcher: RecommendedWatcher =
                match RecommendedWatcher::new(tx, NotifyConfig::default()) {
                    Ok(w) => w,
                    Err(e) => {
                        tracing::error!("failed to create file watcher: {}", e);
                        return;
                    }
                };
            // A watch that cannot be installed means changes are never picked up (typically the
            // unprivileged user cannot traverse the directory): say so instead of staying silent.
            for (path, mode) in [
                (&cfg_watch_path, RecursiveMode::NonRecursive),
                (&zone_watch_dir, RecursiveMode::Recursive),
            ] {
                if let Err(e) = watcher.watch(path, mode) {
                    tracing::error!(
                        "hot reload disabled for {}: cannot watch it ({}). Check that the server user can read the path and all its parent directories",
                        path.display(),
                        e
                    );
                }
            }
            if let Some(g) = geoip_path.as_ref().and_then(|g| g.parent()) {
                if !g.starts_with(&zone_watch_dir) {
                    if let Err(e) = watcher.watch(g, RecursiveMode::NonRecursive) {
                        tracing::error!(
                            "GeoIP database changes will not be picked up: cannot watch {} ({})",
                            g.display(),
                            e
                        );
                    }
                }
            }
            for evt in rx {
                let Ok(evt) = evt else { continue };
                // only real content changes; ignore access events and temp files
                let interesting = matches!(
                    evt.kind,
                    notify::EventKind::Create(_)
                        | notify::EventKind::Modify(_)
                        | notify::EventKind::Remove(_)
                ) && evt.paths.iter().any(|p| {
                    let n = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    !(n.ends_with(".tmp") || n.starts_with('.'))
                        && !p.components().any(|c| c.as_os_str() == ".orphaned")
                });
                if interesting && reload_tx.send(()).is_err() {
                    break;
                }
            }
        });
        {
            let handler = handler.clone();
            let token = server.shutdown_token().clone();
            let config_path = config_path.to_path_buf();
            #[cfg(feature = "prometheus-metrics")]
            let reload_readiness = readiness.clone();
            tokio::spawn(async move {
                while reload_rx.recv().await.is_some() {
                    // debounce: a publication touches several files
                    tokio::time::sleep(StdDuration::from_millis(300)).await;
                    while reload_rx.try_recv().is_ok() {}
                    let reloaded = reload_zones(
                        &config_path,
                        &zonedir_for_reload,
                        &startup_fingerprint,
                        &nsid_final,
                        &handler,
                        &|| token.cancel(),
                    )
                    .await;
                    #[cfg(not(feature = "prometheus-metrics"))]
                    let _ = reloaded;
                    #[cfg(feature = "prometheus-metrics")]
                    if reloaded {
                        reload_readiness.mark_ready();
                    } else {
                        reload_readiness.mark_not_ready();
                    }
                }
            });
        }

        // config complete, starting!
        banner();

        // TODO: how to do threads? should we do a bunch of listener threads and then query threads?
        // Ideally the processing would be n-threads for receiving, which hand off to m-threads for
        //  request handling. It would generally be the case that n <= m.
        info!("server starting up, awaiting connections...");
        match server.block_until_done().await {
            Ok(()) => {
                // we're exiting for some reason...
                info!("Hickory DNS {} stopping", env!("CARGO_PKG_VERSION"));
            }
            Err(e) => {
                let error_msg = format!(
                    "Hickory DNS {} has encountered an error: {}",
                    env!("CARGO_PKG_VERSION"),
                    e
                );

                error!("{}", error_msg);
                panic!("{}", error_msg);
            }
        };

        // Shut down the Prometheus metrics server after the DNS server has gracefully shut down.
        #[cfg(feature = "prometheus-metrics")]
        if let Some(server) = prometheus_server_opt {
            server.stop().await;
        }

        #[cfg(feature = "metrics")]
        process_metrics_collector.abort();

        Ok(())
    }
}

/// Debug rendering of everything in the config except the zones.
fn listener_fingerprint(config: &mut Config) -> String {
    let zones = std::mem::take(&mut config.zones);
    let fp = format!("{config:?}");
    config.zones = zones;
    fp
}

/// Fingerprint the first file store of a configured zone.
fn zone_config_fingerprint(zone: &ZoneConfig, zone_dir: &Path) -> Option<String> {
    match &zone.zone_type_config {
        ZoneTypeConfig::Primary(config) | ZoneTypeConfig::Secondary(config) => {
            config.stores.iter().find_map(|store| match store {
                ServerStoreConfig::File(file) => zone_fingerprint(&zone_dir.join(&file.zone_path)),
                _ => None,
            })
        }
        ZoneTypeConfig::External { .. } => None,
    }
}

/// Fingerprint a zone file so a reload can skip zones whose content did not change.
fn zone_fingerprint(path: &Path) -> Option<String> {
    let metadata = std::fs::metadata(path).ok()?;
    let modified = metadata.modified().ok()?;
    let nanos = modified
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    Some(format!("{}:{}", metadata.len(), nanos))
}

/// Re-read the configuration and swap in a freshly built catalog. Any problem
/// keeps the catalog that is currently serving: a bad publication must never
/// take the server down.
async fn reload_zones(
    config_path: &Path,
    zonedir: &Option<PathBuf>,
    startup_fingerprint: &str,
    nsid: &Option<NSIDPayload>,
    handler: &SwapHandler,
    restart: &(dyn Fn() + Send + Sync),
) -> bool {
    let mut config = match Config::read_config(config_path) {
        Ok(c) => c,
        Err(e) => {
            error!("reload skipped, cannot read {config_path:?}: {e}");
            return false;
        }
    };
    if listener_fingerprint(&mut config) != startup_fingerprint {
        tracing::warn!("listener/privilege configuration changed: restarting to apply it");
        restart();
        return false;
    }
    let zone_dir = zonedir.clone().unwrap_or_else(|| config.directory.clone());
    let serving = handler.current_catalog();
    let mut catalog = Catalog::new();
    catalog.clone_handlers_from(&serving);
    catalog.set_nsid(nsid.clone());
    let count = config.zones.len();
    let mut fingerprints = HashMap::new();
    let mut reused = 0usize;
    let mut notify_after_reload = Vec::new();
    for zone in config.zones {
        let zone_name = match zone.zone() {
            Ok(n) => n,
            Err(e) => {
                error!("reload aborted, bad zone name: {e}");
                return false;
            }
        };
        let key = zone_name.to_string();
        let lower: hickory_server::proto::rr::LowerName = zone_name.clone().into();
        let fingerprint = zone_config_fingerprint(&zone, &zone_dir);

        if fingerprint.is_some()
            && fingerprint == handler.zone_fingerprint(&key)
            && serving.find(&lower).is_some()
        {
            fingerprints.insert(key, fingerprint.expect("fingerprint checked"));
            reused += 1;
            continue;
        }

        let notify_peers = zone.notify_peers().to_vec();
        match zone.load(&zone_dir).await {
            Ok(handlers) => {
                catalog.upsert(zone_name.clone().into(), handlers);
                if !notify_peers.is_empty() {
                    notify_after_reload.push((zone_name, notify_peers));
                }
                if let Some(fingerprint) = fingerprint {
                    fingerprints.insert(key, fingerprint);
                }
            }
            Err(e) => {
                error!(
                    "reload aborted, zone {zone_name} failed to load (still serving the previous data): {e}"
                );
                return false;
            }
        }
    }
    handler.swap(catalog);
    handler.set_zone_fingerprints(fingerprints);
    #[cfg(feature = "prometheus-metrics")]
    {
        describe_counter!(
            "outis_zone_reload_rebuilt_zones_total",
            "Number of zone handlers rebuilt during configuration reloads."
        );
        describe_counter!(
            "outis_zone_reload_reused_zones_total",
            "Number of unchanged zone handlers reused during configuration reloads."
        );
        counter!("outis_zone_reload_rebuilt_zones_total")
            .increment((count.saturating_sub(reused)) as u64);
        counter!("outis_zone_reload_reused_zones_total").increment(reused as u64);
    }
    info!(
        "reloaded {count} zone(s), {reused} unchanged (reload #{})",
        handler.reloads()
    );
    for (zone_name, peers) in notify_after_reload {
        let zone_dir = zone_dir.clone();
        tokio::spawn(async move {
            for peer in peers {
                send_zone_notify(zone_name.clone(), peer, &zone_dir).await;
            }
        });
    }
    true
}

async fn send_zone_notify(zone: Name, peer: NotifyPeerConfig, _zone_dir: &Path) {
    const ATTEMPTS: usize = 3;
    const CONNECT_TIMEOUT: StdDuration = StdDuration::from_secs(3);
    const REQUEST_TIMEOUT: StdDuration = StdDuration::from_secs(3);
    #[cfg(feature = "__dnssec")]
    let signer = match notify_signer(&peer, _zone_dir) {
        Ok(signer) => signer,
        Err(error) => {
            error!("cannot notify {} for {zone}: {error}", peer.address);
            return;
        }
    };
    for attempt in 0..ATTEMPTS {
        let provider = TokioRuntimeProvider::new();
        let (connect, sender) = TcpClientStream::new(peer.address, None, None, provider);
        let stream = match tokio::time::timeout(CONNECT_TIMEOUT, connect).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => {
                if attempt + 1 == ATTEMPTS {
                    error!(
                        "NOTIFY to {} for {zone} failed after {ATTEMPTS} attempts: {error}",
                        peer.address
                    );
                }
                retry_notify_delay(attempt).await;
                continue;
            }
            Err(_) => {
                if attempt + 1 == ATTEMPTS {
                    error!(
                        "NOTIFY connection to {} for {zone} timed out after {ATTEMPTS} attempts",
                        peer.address
                    );
                }
                retry_notify_delay(attempt).await;
                continue;
            }
        };
        #[cfg(feature = "__dnssec")]
        let (mut client, background) = match signer.clone() {
            Some(signer) => Client::<TokioRuntimeProvider>::from_sender(
                DnsMultiplexer::new(stream, sender).with_signer(signer),
            ),
            None => Client::<TokioRuntimeProvider>::new(stream, sender),
        };
        #[cfg(not(feature = "__dnssec"))]
        let (mut client, background) = Client::<TokioRuntimeProvider>::new(stream, sender);
        let background = tokio::spawn(background);
        let response = tokio::time::timeout(
            REQUEST_TIMEOUT,
            client.notify::<RecordSet>(zone.clone(), DNSClass::IN, RecordType::SOA, None),
        )
        .await;
        background.abort();
        match response {
            Ok(Ok(response))
                if response.response_code() == hickory_server::proto::op::ResponseCode::NoError
                    || response.response_code()
                        == hickory_server::proto::op::ResponseCode::NotImp =>
            {
                info!("NOTIFY for {zone} acknowledged by {}", peer.address);
                return;
            }
            Ok(Ok(response)) => {
                error!(
                    "NOTIFY for {zone} refused by {}: {}",
                    peer.address,
                    response.response_code()
                );
                return;
            }
            Ok(Err(error)) => {
                if attempt + 1 == ATTEMPTS {
                    error!(
                        "NOTIFY to {} for {zone} failed after {ATTEMPTS} attempts: {error}",
                        peer.address
                    );
                }
            }
            Err(_) => {
                if attempt + 1 == ATTEMPTS {
                    error!(
                        "NOTIFY to {} for {zone} timed out after {ATTEMPTS} attempts",
                        peer.address
                    );
                }
            }
        }
        retry_notify_delay(attempt).await;
    }
}

async fn retry_notify_delay(attempt: usize) {
    let delay = StdDuration::from_millis(200).saturating_mul(1 << attempt.min(4));
    tokio::time::sleep(delay).await;
}

/// A NOTIFY is only a hint. Re-read the active config, require a configured
/// secondary/master relationship, then fetch a complete AXFR before replacing
/// the served zone file. The existing file and catalog remain authoritative
/// until the transfer validates and the atomic rename succeeds.
async fn refresh_secondary_from_notify(
    requested_zone: hickory_server::proto::rr::LowerName,
    source: SocketAddr,
    config_path: &Path,
    zone_dir: &Path,
) -> Result<bool, String> {
    let config = Config::read_config(config_path)
        .map_err(|error| format!("could not read active config: {error}"))?;
    let zone = config
        .zones
        .into_iter()
        .find(|zone| {
            zone.zone()
                .map(|name| hickory_server::proto::rr::LowerName::from(name) == requested_zone)
                .unwrap_or(false)
        })
        .ok_or_else(|| format!("NOTIFY zone {requested_zone} is not configured"))?;
    let ZoneTypeConfig::Secondary(server_config) = &zone.zone_type_config else {
        return Ok(false);
    };
    let master = zone
        .masters()
        .iter()
        .find(|master| master.address.ip() == source.ip())
        .cloned()
        .ok_or_else(|| {
            format!(
                "NOTIFY source {} is not a configured primary for {requested_zone}",
                source.ip()
            )
        })?;
    let file = server_config
        .stores
        .iter()
        .find_map(|store| match store {
            ServerStoreConfig::File(file) => Some(file.zone_path.clone()),
            _ => None,
        })
        .ok_or_else(|| format!("secondary {requested_zone} has no file-backed zone store"))?;
    let destination = zone_dir.join(file);

    let mut last_error = String::from("AXFR failed without an error detail");
    for attempt in 0..3 {
        match fetch_zone_axfr(&master, requested_zone.clone().into(), zone_dir).await {
            Ok(records) => match atomically_install_axfr(&requested_zone, &destination, &records) {
                Ok(changed) => {
                    info!(%requested_zone, %source, changed, "secondary AXFR from configured primary validated");
                    return Ok(changed);
                }
                Err(error) => last_error = error,
            },
            Err(error) => last_error = error,
        }
        if attempt < 2 {
            retry_notify_delay(attempt).await;
        }
    }
    Err(format!(
        "AXFR refresh for {requested_zone} failed after three attempts: {last_error}"
    ))
}

fn secondary_soa_timers(zone: &Name, path: &Path) -> (StdDuration, StdDuration, StdDuration) {
    let timers = fs::read_to_string(path)
        .ok()
        .and_then(|contents| {
            ZoneParser::new(contents, None, Some(zone.clone()))
                .parse()
                .ok()
        })
        .and_then(|(_, records)| {
            records.into_iter().find_map(|(_, rrset)| {
                if rrset.record_type() != RecordType::SOA {
                    return None;
                }
                rrset.into_iter().find_map(|record| match record.data() {
                    RData::SOA(soa) => Some((soa.refresh(), soa.retry(), soa.expire())),
                    _ => None,
                })
            })
        })
        .unwrap_or((3600, 300, 604800));
    (
        StdDuration::from_secs(timers.0.max(1) as u64),
        StdDuration::from_secs(timers.1.max(1) as u64),
        StdDuration::from_secs(timers.2.max(1) as u64),
    )
}

async fn secondary_refresh_loop(
    zone: hickory_server::proto::rr::LowerName,
    masters: Vec<NotifyPeerConfig>,
    file: PathBuf,
    (mut refresh, mut retry, mut expire): (StdDuration, StdDuration, StdDuration),
    initial_refresh_succeeded: bool,
    config_path: PathBuf,
    zone_dir: PathBuf,
    reload_tx: tokio::sync::mpsc::UnboundedSender<()>,
    handler: SwapHandler,
) {
    let modified_age = fs::metadata(&file)
        .and_then(|metadata| metadata.modified())
        .ok()
        .and_then(|modified| SystemTime::now().duration_since(modified).ok())
        .unwrap_or_default();
    let mut last_success = Instant::now()
        .checked_sub(modified_age)
        .unwrap_or_else(Instant::now);
    let mut withdrawn = false;
    let mut delay = if initial_refresh_succeeded {
        refresh
    } else {
        retry
    };
    loop {
        tokio::time::sleep(delay).await;
        let mut errors = Vec::new();
        let mut refreshed = false;
        for master in &masters {
            match refresh_secondary_from_notify(
                zone.clone(),
                master.address,
                &config_path,
                &zone_dir,
            )
            .await
            {
                Ok(changed) => {
                    refreshed = true;
                    last_success = Instant::now();
                    let was_withdrawn = withdrawn;
                    if was_withdrawn {
                        handler.mark_zone_fresh(&zone);
                        withdrawn = false;
                    }
                    if changed || was_withdrawn {
                        // The transfer may be valid but carry the current serial.
                        // Only reload the serving catalog when the file changed.
                        let _ = reload_tx.send(());
                    }
                    break;
                }
                Err(error) => errors.push(error),
            }
        }
        if refreshed {
            let origin: Name = zone.clone().into();
            (refresh, retry, expire) = secondary_soa_timers(&origin, &file);
            delay = refresh;
        } else {
            warn!(
                %zone,
                errors = %errors.join("; "),
                "scheduled secondary refresh failed; preserving last-known-good zone"
            );
            delay = retry;
        }
        if !refreshed && !withdrawn && last_success.elapsed() >= expire {
            handler.mark_zone_expired(zone.clone());
            withdrawn = true;
            error!(%zone, ?expire, "secondary SOA expire timer elapsed; failing queries closed until refresh succeeds");
        }
    }
}

async fn fetch_zone_axfr(
    master: &NotifyPeerConfig,
    zone: Name,
    zone_dir: &Path,
) -> Result<Vec<Record>, String> {
    const TIMEOUT: StdDuration = StdDuration::from_secs(10);
    let provider = TokioRuntimeProvider::new();
    let (connect, sender) = TcpClientStream::new(master.address, None, None, provider);
    let stream = tokio::time::timeout(TIMEOUT, connect)
        .await
        .map_err(|_| format!("TCP connect to {} timed out", master.address))?
        .map_err(|error| format!("TCP connect to {} failed: {error}", master.address))?;

    #[cfg(feature = "__dnssec")]
    let (mut client, background) = {
        let signer = notify_signer(master, zone_dir)?;
        match signer {
            Some(signer) => Client::<TokioRuntimeProvider>::from_sender(
                DnsMultiplexer::new(stream, sender).with_signer(signer),
            ),
            None => Client::<TokioRuntimeProvider>::new(stream, sender),
        }
    };
    #[cfg(not(feature = "__dnssec"))]
    let (mut client, background) = Client::<TokioRuntimeProvider>::new(stream, sender);
    let background = tokio::spawn(background);

    let mut transfer = client.zone_transfer(zone, None);
    let mut records = Vec::new();
    let result = async {
        while let Some(response) = tokio::time::timeout(TIMEOUT, transfer.next())
            .await
            .map_err(|_| String::from("AXFR response timed out"))?
        {
            let response = response.map_err(|error| format!("invalid AXFR response: {error}"))?;
            if response.response_code() != hickory_server::proto::op::ResponseCode::NoError {
                return Err(format!("primary returned {}", response.response_code()));
            }
            records.extend(response.answers().iter().cloned());
            if records.len() > 100_000 {
                return Err(String::from("AXFR exceeds the 100000-record safety limit"));
            }
        }
        Ok(records)
    }
    .await;
    background.abort();
    result
}

fn atomically_install_axfr(
    zone: &Name,
    destination: &Path,
    records: &[Record],
) -> Result<bool, String> {
    if records.len() < 2 {
        return Err(String::from("AXFR did not contain SOA transfer boundaries"));
    }
    let (Some(first_soa), Some(last_soa)) = (
        records.first().and_then(|record| match record.data() {
            RData::SOA(soa) if record.name() == zone => Some(soa),
            _ => None,
        }),
        records.last().and_then(|record| match record.data() {
            RData::SOA(soa) if record.name() == zone => Some(soa),
            _ => None,
        }),
    ) else {
        return Err(String::from("AXFR has invalid opening or closing SOA"));
    };
    if first_soa != last_soa {
        return Err(String::from("AXFR SOA boundaries do not match"));
    }

    let zone_ascii = zone.to_ascii().to_ascii_lowercase();
    let mut content = format!("$ORIGIN {zone}\n");
    for record in records.iter().take(records.len() - 1) {
        let owner = record.name().to_ascii().to_ascii_lowercase();
        if owner != zone_ascii && !owner.ends_with(&format!(".{zone_ascii}")) {
            return Err(format!("AXFR contains out-of-zone owner {owner}"));
        }
        content.push_str(&record.to_string());
        content.push('\n');
        if content.len() > 32 * 1024 * 1024 {
            return Err(String::from(
                "AXFR exceeds the 32 MiB zone-file safety limit",
            ));
        }
    }
    let (_, parsed) = ZoneParser::new(content.clone(), None, Some(zone.clone()))
        .parse()
        .map_err(|error| format!("AXFR zone failed Hickory parser validation: {error}"))?;
    if parsed.is_empty()
        || !parsed
            .iter()
            .any(|(_, rrset)| rrset.record_type() == RecordType::SOA)
    {
        return Err(String::from(
            "AXFR zone file is missing its SOA after parsing",
        ));
    }

    let old_soa = fs::read_to_string(destination)
        .ok()
        .and_then(|old| ZoneParser::new(old, None, Some(zone.clone())).parse().ok())
        .and_then(|(_, records)| {
            records.into_iter().find_map(|(_, rrset)| {
                if rrset.record_type() == RecordType::SOA {
                    rrset.into_iter().find_map(|record| match record.data() {
                        RData::SOA(soa) => Some(soa.clone()),
                        _ => None,
                    })
                } else {
                    None
                }
            })
        });
    if let Some(old) = old_soa {
        let serial = first_soa.serial();
        let delta = serial.wrapping_sub(old.serial());
        if serial == old.serial() || delta >= (1 << 31) {
            return Ok(false); // stale/replayed NOTIFY must never roll a secondary backwards
        }
    }

    let parent = destination
        .parent()
        .ok_or_else(|| String::from("zone file path has no parent directory"))?;
    let file_name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| String::from("zone file path has no valid file name"))?;
    let temp_path = parent.join(format!(".{file_name}.{}.tmp", Uuid::new_v4()));
    let result = (|| -> Result<(), String> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
            .map_err(|error| format!("create staged AXFR file failed: {error}"))?;
        file.write_all(content.as_bytes())
            .map_err(|error| format!("write staged AXFR file failed: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("sync staged AXFR file failed: {error}"))?;
        fs::rename(&temp_path, destination)
            .map_err(|error| format!("atomic zone file replacement failed: {error}"))?;
        if let Ok(directory) = fs::File::open(parent) {
            let _ = directory.sync_all();
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result.map(|()| true)
}

#[cfg(feature = "__dnssec")]
fn notify_signer(
    peer: &NotifyPeerConfig,
    zone_dir: &Path,
) -> Result<Option<hickory_proto::rr::TSigner>, String> {
    use std::str::FromStr;
    let Some(config) = peer.tsig.as_ref() else {
        return Ok(None);
    };
    let path = zone_dir.join(&config.key_file);
    let key = std::fs::read(&path).map_err(|error| {
        format!(
            "failed to read NOTIFY TSIG key file {}: {error}",
            path.display()
        )
    })?;
    let name = Name::from_str(&config.name)
        .map_err(|error| format!("invalid NOTIFY TSIG key name: {error}"))?;
    hickory_proto::rr::TSigner::new(key, config.algorithm.clone(), name, config.fudge)
        .map(Some)
        .map_err(|error| format!("invalid NOTIFY TSIG key configuration: {error}"))
}

struct ServerSetup<'a> {
    listen_addrs: Vec<IpAddr>,
    server: &'a mut Server<SwapHandler>,
    tcp_request_timeout: Duration,
    #[cfg(any(
        feature = "__tls",
        feature = "__https",
        feature = "__quic",
        feature = "__h3"
    ))]
    cert_resolver: Option<Arc<dyn ResolvesServerCert>>,
    #[cfg(any(
        feature = "__tls",
        feature = "__https",
        feature = "__quic",
        feature = "__h3"
    ))]
    ssl_keylog_enabled: bool,
}

impl ServerSetup<'_> {
    fn udp(&mut self, port: u16) -> Result<(), String> {
        for addr in &self.listen_addrs {
            info!("binding UDP to {addr:?}");

            let udp_socket = build_udp_socket(*addr, port)
                .map_err(|err| format!("failed to bind to UDP socket address {addr:?}: {err}"))?;

            info!(
                "listening for UDP on {:?}",
                udp_socket
                    .local_addr()
                    .map_err(|err| format!("failed to lookup local address: {err}"))?
            );

            self.server.register_socket(udp_socket);
        }

        Ok(())
    }

    fn tcp(&mut self, port: u16) -> Result<(), String> {
        for addr in &self.listen_addrs {
            info!("binding TCP to {addr:?}");

            let tcp_listener = build_tcp_listener(*addr, port)
                .map_err(|err| format!("failed to bind to TCP socket address {addr:?}: {err}"))?;

            info!(
                "listening for TCP on {:?}",
                tcp_listener
                    .local_addr()
                    .map_err(|err| format!("failed to lookup local address: {err}"))?
            );

            self.server
                .register_listener(tcp_listener, self.tcp_request_timeout);
        }

        Ok(())
    }

    #[cfg(feature = "__tls")]
    fn tls(&mut self, port: u16) -> Result<(), String> {
        let Some(cert_resolver) = &self.cert_resolver else {
            return Ok(());
        };

        for addr in &self.listen_addrs {
            info!("binding TLS to {addr:?}");

            let tls_listener = build_tcp_listener(*addr, port)
                .map_err(|err| format!("failed to bind to TLS socket address {addr:?}: {err}"))?;

            info!(
                "listening for TLS on {:?}",
                tls_listener
                    .local_addr()
                    .map_err(|err| format!("failed to lookup local address: {err}"))?
            );

            let mut tls_config = default_tls_server_config(b"dot", cert_resolver.clone())
                .map_err(|err| format!("failed to build default TLS config: {err}"))?;
            if self.ssl_keylog_enabled {
                warn!("DoT SSL_KEYLOG_FILE support enabled");
                tls_config.key_log = Arc::new(KeyLogFile::new());
            }

            self.server
                .register_tls_listener_with_tls_config(
                    tls_listener,
                    self.tcp_request_timeout,
                    Arc::new(tls_config),
                )
                .map_err(|err| format!("failed to register TLS listener: {err}"))?;
        }
        Ok(())
    }

    #[cfg(feature = "__https")]
    fn https(
        &mut self,
        port: u16,
        http_endpoint: &str,
        dns_hostname: Option<&str>,
    ) -> Result<(), String> {
        let Some(cert_resolver) = &self.cert_resolver else {
            return Ok(());
        };

        for addr in &self.listen_addrs {
            info!("binding HTTPS to {addr:?}");

            let https_listener = build_tcp_listener(*addr, port)
                .map_err(|err| format!("failed to bind to HTTPS socket address {addr:?}: {err}"))?;

            info!(
                "listening for HTTPS on {:?}",
                https_listener
                    .local_addr()
                    .map_err(|err| format!("failed to lookup local address: {err}"))?
            );

            let mut tls_config = default_tls_server_config(b"h2", cert_resolver.clone())
                .map_err(|err| format!("failed to build default TLS config: {err}"))?;
            if self.ssl_keylog_enabled {
                warn!("DoH SSL_KEYLOG_FILE support enabled");
                tls_config.key_log = Arc::new(KeyLogFile::new());
            }

            self.server
                .register_https_listener_with_tls_config(
                    https_listener,
                    self.tcp_request_timeout,
                    Arc::new(tls_config),
                    dns_hostname.map(|s| s.to_owned()),
                    http_endpoint.to_owned(),
                )
                .map_err(|err| format!("failed to register HTTPS listener: {err}"))?;
        }

        Ok(())
    }

    #[cfg(feature = "__quic")]
    fn quic(&mut self, port: u16) -> Result<(), String> {
        let Some(cert_resolver) = &self.cert_resolver else {
            return Ok(());
        };

        for addr in &self.listen_addrs {
            info!("Binding QUIC to {addr:?}");

            let quic_listener = build_udp_socket(*addr, port)
                .map_err(|err| format!("failed to bind to QUIC socket address {addr:?}: {err}"))?;

            info!(
                "listening for QUIC on {:?}",
                quic_listener
                    .local_addr()
                    .map_err(|err| format!("failed to lookup local address: {err}"))?
            );

            let mut tls_config = default_tls_server_config(b"doq", cert_resolver.clone())
                .map_err(|err| format!("failed to build default TLS config: {err}"))?;
            if self.ssl_keylog_enabled {
                warn!("DoQ SSL_KEYLOG_FILE support enabled");
                tls_config.key_log = Arc::new(KeyLogFile::new());
            }

            self.server
                .register_quic_listener_and_tls_config(
                    quic_listener,
                    self.tcp_request_timeout,
                    Arc::new(tls_config),
                )
                .map_err(|err| format!("failed to register QUIC listener: {err}"))?;
        }
        Ok(())
    }

    #[cfg(feature = "__h3")]
    fn h3(&mut self, port: u16) -> Result<(), String> {
        let Some(cert_resolver) = &self.cert_resolver else {
            return Ok(());
        };

        for addr in &self.listen_addrs {
            info!("Binding HTTP/3 to {addr:?}");

            let h3_socket = build_udp_socket(*addr, port).map_err(|err| {
                format!("failed to bind to HTTP/3 socket address {addr:?}: {err}")
            })?;

            info!(
                "listening for HTTP/3 on {:?}",
                h3_socket
                    .local_addr()
                    .map_err(|err| format!("failed to lookup local address: {err}"))?
            );

            let mut tls_config = default_tls_server_config(b"h3", cert_resolver.clone())
                .map_err(|err| format!("failed to build default TLS config: {err}"))?;
            if self.ssl_keylog_enabled {
                warn!("DoH3 SSL_KEYLOG_FILE support enabled");
                tls_config.key_log = Arc::new(KeyLogFile::new());
            }

            self.server
                .register_h3_listener_with_tls_config(
                    h3_socket,
                    self.tcp_request_timeout,
                    Arc::new(tls_config),
                    None,
                )
                .map_err(|err| format!("failed to register HTTP/3 listener: {err}"))?;
        }
        Ok(())
    }
}

fn banner() {
    #[cfg(feature = "ascii-art")]
    const HICKORY_DNS_LOGO: &str = include_str!("hickory-dns.ascii");

    #[cfg(not(feature = "ascii-art"))]
    const HICKORY_DNS_LOGO: &str = "Hickory DNS";

    info!("");
    for line in HICKORY_DNS_LOGO.lines() {
        info!(" {line}");
    }
    info!("");
}

/// Build a TcpListener for a given IP, port pair; IPv6 listeners will not accept v4 connections
fn build_tcp_listener(ip: IpAddr, port: u16) -> Result<TcpListener, Error> {
    let sock = if ip.is_ipv4() {
        Socket::new(Domain::IPV4, Type::STREAM, None)?
    } else {
        let s = Socket::new(Domain::IPV6, Type::STREAM, None)?;
        s.set_only_v6(true)?;
        s
    };

    sock.set_nonblocking(true)?;

    let s_addr = SocketAddr::new(ip, port);
    sock.bind(&s_addr.into())?;

    // this is a fairly typical backlog value, but we don't have any good data to support it as of yet
    sock.listen(128)?;

    TcpListener::from_std(sock.into())
}

/// Build a UdpSocket for a given IP, port pair; IPv6 sockets will not accept v4 connections
fn build_udp_socket(ip: IpAddr, port: u16) -> Result<UdpSocket, Error> {
    let sock = if ip.is_ipv4() {
        Socket::new(Domain::IPV4, Type::DGRAM, None)?
    } else {
        let s = Socket::new(Domain::IPV6, Type::DGRAM, None)?;
        s.set_only_v6(true)?;
        s
    };

    sock.set_nonblocking(true)?;

    let s_addr = SocketAddr::new(ip, port);
    sock.bind(&s_addr.into())?;

    UdpSocket::from_std(sock.into())
}

/// Drop privileges on Unix systems if running as root. Errors that prevent dropping privileges will
/// halt the server.  This must be called after binding to low numbered sockets is complete.
#[cfg(target_family = "unix")]
fn check_drop_privs(user: &str, group: &str) -> Result<(), String> {
    use libc::{getegid, geteuid, getgid, getgrnam, getpwnam, getuid, setgid, setuid};
    use std::ffi::CString;

    // These calls are guaranteed to succeed in a POSIX-conforming environment. In non-conforming
    // environments, implementations may return -1 to indicate a process running without an
    // associated UID/EUID/GID/EGID. In that case, our main block below will not execute as
    // libc typedefs uid_t and gid_t to u32; -1 will be u32::MAX.
    //
    // POSIX reference: IEEE Std 1003.1-1024 getuid, geteuid, getgid, and getegid specifications
    // https://pubs.opengroup.org/onlinepubs/9799919799/functions/getuid.html
    // https://pubs.opengroup.org/onlinepubs/9799919799/functions/geteuid.html
    // https://pubs.opengroup.org/onlinepubs/9799919799/functions/getgid.html
    // https://pubs.opengroup.org/onlinepubs/9799919799/functions/getegid.html
    let (uid, gid, euid, egid) = unsafe { (getuid(), getgid(), geteuid(), getegid()) };

    if uid == 0 || euid == 0 {
        info!(
            "running as root (uid: {uid} gid: {gid} euid: {euid} egid: {egid})...dropping privileges.",
        );

        let Ok(user_cstring) = CString::new(user) else {
            return Err(format!("unable to create CString for user {user}"));
        };

        let Ok(group_cstring) = CString::new(group) else {
            return Err(format!(
                "unable to create CString for group {group}. Exiting."
            ));
        };

        // These functions must be supplied a NULL-terminated string, which is guaranteed by
        // std::ffi::CString.  Upon success, they will return a pointer to a struct passwd or
        // struct group, or NULL upon failure. Testing for a NULL return value is mandatory.
        //
        // POSIX reference: IEEE Std 1003.1-1024 getpwnam and getgrnam specifications
        // https://pubs.opengroup.org/onlinepubs/9799919799/functions/getpwnam.html
        // https://pubs.opengroup.org/onlinepubs/9799919799/functions/getgrnam.html
        let (user_info, group_info) = unsafe {
            (
                getpwnam(user_cstring.as_ptr()),
                getgrnam(group_cstring.as_ptr()),
            )
        };

        if user_info.is_null() {
            return Err(format!("unable to lookup user '{user}'. Exiting."));
        }

        if group_info.is_null() {
            return Err(format!("unable to lookup group '{group}'. Exiting."));
        }

        // These functions must be supplied a gid_t (setgid) and uid_t (setuid), which are
        // supplied by the passwd and group structs returned by getpwnam and getgrnam.
        // The structs are tested to be valid by the calls to is_null() above.
        //
        // The call to setgid must be completed before the call to setuid is made or the
        // process will almost certainly lack the privileges necessary to switch its real gid.
        //
        // POSIX reference: IEEE Std 1003.1-1024 setgid and setuid specifications
        // https://pubs.opengroup.org/onlinepubs/9799919799/functions/setgid.html
        // https://pubs.opengroup.org/onlinepubs/9799919799/functions/setuid.html
        let (setgid_rc, setuid_rc) =
            unsafe { (setgid((*group_info).gr_gid), setuid((*user_info).pw_uid)) };

        if setgid_rc < 0 {
            return Err("unable to set gid. Exiting.".into());
        }

        if setuid_rc < 0 {
            return Err("unable to set uid. Exiting.".into());
        }
    }

    let (uid, gid, euid, egid) = unsafe { (getuid(), getgid(), geteuid(), getegid()) };

    info!("now running as uid: {uid}, gid: {gid} (euid: {euid}, egid: {egid})",);
    Ok(())
}

fn parse_nsid_payload(raw_payload: &str) -> Result<NSIDPayload, ProtoError> {
    let bytes = if let Some(hex_str) = raw_payload.strip_prefix("0x") {
        hex::decode(hex_str)
            .map_err(|e| ProtoError::from(format!("invalid NSID hex encoding: {e}")))?
    } else {
        raw_payload.as_bytes().to_vec()
    };
    NSIDPayload::new(bytes)
}

#[cfg(target_family = "unix")]
const DEFAULT_USER: &str = "nobody";
#[cfg(target_family = "unix")]
const DEFAULT_GROUP: &str = "nobody";

/// Debian/Ubuntu have no `nobody` group (it is called `nogroup`); fall back to
/// it so the privilege drop does not abort when run as root with defaults.
#[cfg(target_family = "unix")]
fn default_group() -> String {
    let exists = |name: &str| {
        std::ffi::CString::new(name)
            .map(|c| !unsafe { libc::getgrnam(c.as_ptr()) }.is_null())
            .unwrap_or(false)
    };
    if !exists(DEFAULT_GROUP) && exists("nogroup") {
        "nogroup".to_string()
    } else {
        DEFAULT_GROUP.to_string()
    }
}

#[cfg(test)]
mod tests {
    use hickory_proto::rr::rdata::opt::NSIDPayload;

    use super::parse_nsid_payload;

    #[test]
    fn test_hex_nsid_payload() {
        let expected = NSIDPayload::new(vec![0xC0, 0xFF, 0xEE]).unwrap();
        let value = parse_nsid_payload("0xC0FFEE").unwrap();
        assert_eq!(value, expected);
    }

    #[test]
    fn test_string_nsid_payload() {
        let string_value = "HickoryDNS";
        let expected = NSIDPayload::new(string_value.as_bytes()).unwrap();
        let value = parse_nsid_payload(string_value).unwrap();
        assert_eq!(value, expected);
    }

    #[test]
    fn test_nsid_payload_too_long() {
        let too_large = "x".repeat(u16::MAX as usize + 1);
        let err = parse_nsid_payload(&too_large).unwrap_err();
        assert_eq!(err.to_string(), "NSID EDNS payload too large");
    }
}

#[cfg(test)]
mod reload_fingerprint_tests {
    use super::*;

    #[test]
    fn zone_fingerprint_changes_with_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("example.zone");
        std::fs::write(&path, "$TTL 3600\nexample.com. IN SOA ns.example.com. hostmaster.example.com. 1 7200 3600 1209600 3600\n").unwrap();
        let first = zone_fingerprint(&path).expect("fingerprint");
        std::fs::write(&path, "$TTL 3600\nexample.com. IN SOA ns.example.com. hostmaster.example.com. 2 7200 3600 1209600 3600\n").unwrap();
        let second = zone_fingerprint(&path).expect("fingerprint");
        assert_ne!(first, second);
        assert_eq!(zone_fingerprint(&dir.path().join("missing.zone")), None);
    }

    fn transfer_records(serial: u32, address: &str) -> Vec<Record> {
        let zone = Name::from_ascii("example.test.").unwrap();
        let text = format!(
            "$ORIGIN example.test.\n$TTL 60\n@ IN SOA ns.example.test. hostmaster.example.test. {serial} 1 1 10 1\n@ IN NS ns.example.test.\nns IN A 192.0.2.1\nwww IN A {address}\n"
        );
        let (_, sets) = ZoneParser::new(text, None, Some(zone)).parse().unwrap();
        let mut records: Vec<Record> = sets
            .into_iter()
            .flat_map(|(_, set)| set.into_iter())
            .collect();
        let soa_index = records
            .iter()
            .position(|record| record.data().record_type() == RecordType::SOA)
            .unwrap();
        let soa = records.remove(soa_index);
        records.insert(0, soa.clone());
        records.push(soa);
        records
    }

    #[test]
    fn unchanged_or_stale_axfr_is_successful_without_replacing_last_known_good_file() {
        let dir = tempfile::tempdir().unwrap();
        let zone = Name::from_ascii("example.test.").unwrap();
        let path = dir.path().join("example.zone");

        assert!(atomically_install_axfr(&zone, &path, &transfer_records(2, "192.0.2.2")).unwrap());
        let last_known_good = fs::read(&path).unwrap();

        assert!(
            !atomically_install_axfr(&zone, &path, &transfer_records(2, "192.0.2.99")).unwrap()
        );
        assert!(!atomically_install_axfr(&zone, &path, &transfer_records(1, "192.0.2.1")).unwrap());
        assert_eq!(fs::read(&path).unwrap(), last_known_good);
    }
}
