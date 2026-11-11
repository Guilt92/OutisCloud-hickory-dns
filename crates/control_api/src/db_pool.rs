//! Small PostgreSQL connection pool with automatic reconnect.
//!
//! The control API used to share one `tokio_postgres::Client`: requests were
//! serialised on it and a dropped connection left the API permanently broken.
//! `Pool` keeps N connections, hands them out round-robin through `Deref` (so
//! existing `db.query(..)` call sites keep working, every statement is its own
//! auto-committed unit) and replaces a connection in the background when its
//! driver ends.
//!
//! Replaced connections are intentionally leaked (`Box::leak`): a `Deref` impl
//! must return a plain reference, and a reconnect is a rare event that costs a
//! few kilobytes.

use log::{error, info, warn};
use std::ops::Deref;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio_postgres::{Client, Config, NoTls};

pub struct Pool {
    /// the last slot is reserved for transactions (see [`Pool::begin`])
    slots: Vec<RwLock<&'static Client>>,
    next: AtomicUsize,
    tx_lock: tokio::sync::Mutex<()>,
}

/// Exclusive use of the reserved connection. Statements issued through
/// `client` are the only ones on that session, so `BEGIN … COMMIT` cannot be
/// interleaved with other requests.
pub struct TxConn<'a> {
    _guard: tokio::sync::MutexGuard<'a, ()>,
    pub client: &'static Client,
}

async fn open(cfg: &Config) -> Result<&'static Client, tokio_postgres::Error> {
    let (client, conn) = cfg.connect(NoTls).await?;
    let client: &'static Client = Box::leak(Box::new(client));
    // The driver future ends when the connection drops; `Client::is_closed`
    // then becomes true and the supervisor task below replaces the slot.
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            warn!("postgres connection error: {}", e);
        }
    });
    Ok(client)
}

impl Pool {
    /// Open `size` connections. `search_path` is applied to every connection
    /// (used by the tests to isolate a schema).
    pub async fn connect(url: &str, size: usize, search_path: Option<&str>) -> Result<Arc<Pool>, tokio_postgres::Error> {
        let mut cfg: Config = url.parse()?;
        if let Some(sp) = search_path {
            cfg.options(&format!("-c search_path={}", sp));
        }
        let size = size.max(1);
        let mut slots = Vec::with_capacity(size + 1);
        for _ in 0..=size {
            slots.push(RwLock::new(open(&cfg).await?));
        }
        let pool = Arc::new(Pool { slots, next: AtomicUsize::new(0), tx_lock: tokio::sync::Mutex::new(()) });
        for i in 0..=size {
            let p = pool.clone();
            let cfg = cfg.clone();
            tokio::spawn(async move { p.supervise(i, cfg).await });
        }
        Ok(pool)
    }

    async fn supervise(self: Arc<Self>, idx: usize, cfg: Config) {
        let mut backoff = Duration::from_millis(500);
        loop {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let closed = self.slots[idx].read().map(|c| c.is_closed()).unwrap_or(true);
            if !closed {
                continue;
            }
            match open(&cfg).await {
                Ok(c) => {
                    if let Ok(mut w) = self.slots[idx].write() {
                        *w = c;
                    }
                    info!("postgres connection {} re-established", idx);
                    backoff = Duration::from_millis(500);
                }
                Err(e) => {
                    error!("postgres reconnect {} failed: {} (retrying in {:?})", idx, e, backoff);
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(15));
                }
            }
        }
    }

    /// Number of general-purpose connections currently usable.
    pub fn healthy(&self) -> usize {
        self.slots[..self.slots.len() - 1].iter().filter(|s| s.read().map(|c| !c.is_closed()).unwrap_or(false)).count()
    }

    pub fn size(&self) -> usize {
        self.slots.len() - 1
    }

    /// Check out the reserved connection for a transaction. Any transaction a
    /// cancelled request left open on it is rolled back first.
    pub async fn begin(&self) -> Result<TxConn<'_>, tokio_postgres::Error> {
        let guard = self.tx_lock.lock().await;
        let client = *self.slots[self.slots.len() - 1].read().unwrap_or_else(|e| e.into_inner());
        let _ = client.batch_execute("ROLLBACK").await;
        Ok(TxConn { _guard: guard, client })
    }
}

impl Deref for Pool {
    type Target = Client;
    fn deref(&self) -> &Client {
        let n = self.slots.len() - 1; // the reserved slot is never handed out here
        let start = self.next.fetch_add(1, Ordering::Relaxed);
        for off in 0..n {
            let c = *self.slots[(start + off) % n].read().unwrap_or_else(|e| e.into_inner());
            if !c.is_closed() {
                return c;
            }
        }
        // everything is down: hand out a closed client; the caller gets an
        // error and the supervisors are already reconnecting.
        *self.slots[start % n].read().unwrap_or_else(|e| e.into_inner())
    }
}
