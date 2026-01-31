use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;
use hickory_server::server::Server;
use hickory_server::zone_handler::Catalog;
use hickory_server::store::in_memory::InMemoryZoneHandler;
use hickory_proto::rr::{Name, Record, RecordType, RData, RecordSet, rdata::SOA, RrKey};
use std::collections::BTreeMap;
use tokio::task::JoinHandle;
use hickory_server::zone_handler::ZoneType;
use hickory_server::zone_handler::AxfrPolicy;

pub struct DnsManager {
    inner: Arc<Mutex<HashMap<String, (JoinHandle<()>, tokio::sync::oneshot::Sender<()>)>>>,
}

impl DnsManager {
    pub fn new() -> Self {
        Self { inner: Arc::new(Mutex::new(HashMap::new())) }
    }

    pub async fn start_server(&self, id: &str, bind_addr: SocketAddr) -> anyhow::Result<()> {
        let mut catalog = Catalog::new();

        // empty in-memory zone handler with placeholder SOA to satisfy the server
        let origin = Name::from_ascii("example.com.")?;
        let records: BTreeMap<RrKey, RecordSet> = BTreeMap::new();
        let zone = InMemoryZoneHandler::empty(origin.clone(), ZoneType::Primary, AxfrPolicy::Default, #[cfg(feature = "__dnssec")] None);
        catalog.upsert(origin.to_lowercase(), vec![std::sync::Arc::new(zone)]);

        let mut server = Server::new(catalog);

        // bind UDP socket
        let udp = tokio::net::UdpSocket::bind(bind_addr)?;
        server.register_socket(udp);

        // spawn server run-loop
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let handle = tokio::spawn(async move {
            // wait for shutdown signal
            let _ = rx.await;
            // graceful shutdown
            let _ = server.shutdown_gracefully().await;
        });

        self.inner.lock().await.insert(id.to_string(), (handle, tx));
        Ok(())
    }

    pub async fn stop_server(&self, id: &str) -> anyhow::Result<()> {
        if let Some((handle, tx)) = self.inner.lock().await.remove(id) {
            let _ = tx.send(());
            let _ = handle.await;
        }
        Ok(())
    }
}
