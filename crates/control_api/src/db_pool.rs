//! Small PostgreSQL connection pool with automatic reconnect.
//!
//! The control API used to share one `tokio_postgres::Client`: requests were
//! serialised on it and a dropped connection left the API permanently broken.
//! `Pool` keeps N connections, hands them out round-robin (every statement is
//! its own auto-committed unit) and replaces a connection in the background
//! when its driver ends.

use log::{error, info, warn};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock, Weak};
use std::time::Duration;
use tokio::time::sleep;
use tokio_postgres::types::ToSql;
use tokio_postgres::{Client, Config, Error, NoTls, Row};

pub struct Pool {
    slots: Vec<RwLock<Arc<Client>>>,
    next: AtomicUsize,
    /// A bounded set of independent sessions for multi-statement work. Each
    /// session is exclusively checked out for the lifetime of a transaction.
    tx_slots: Vec<TxSlot>,
    next_tx: AtomicUsize,
    tenant_locks: std::sync::Mutex<std::collections::HashMap<String, Weak<tokio::sync::Mutex<()>>>>,
    cfg: Config,
    #[cfg(test)]
    queries: AtomicUsize,
}

/// A PostgreSQL session advisory lock held on a dedicated connection. The lock is released
/// when the guard is dropped (the connection closes), or by the server if this process dies.
pub struct AdvisoryLock {
    _client: Client,
}

/// Exclusive use of one transaction session. Statements issued through
/// `client()` cannot be interleaved with another transaction on that session.
pub struct TxConn {
    _guard: tokio::sync::OwnedMutexGuard<()>,
    _tenant_guard: Option<tokio::sync::OwnedMutexGuard<()>>,
    client: Arc<Client>,
}

struct TxSlot {
    client: RwLock<Arc<Client>>,
    lock: Arc<tokio::sync::Mutex<()>>,
}

impl TxConn {
    pub fn client(&self) -> &Client {
        &self.client
    }
}

async fn open(cfg: &Config) -> Result<Arc<Client>, tokio_postgres::Error> {
    let (client, conn) = cfg.connect(NoTls).await?;
    let client = Arc::new(client);
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
    /// Open `size` general-purpose and `size` transaction connections.
    /// Transaction capacity is therefore bounded by the configured pool size,
    /// while each transaction owns a dedicated PostgreSQL session.
    pub async fn connect(
        url: &str,
        size: usize,
        search_path: Option<&str>,
    ) -> Result<Arc<Pool>, tokio_postgres::Error> {
        Self::connect_with_transaction_size(url, size, size.min(4), search_path).await
    }

    /// Open the query pool and a separately bounded transaction pool.
    pub async fn connect_with_transaction_size(
        url: &str,
        size: usize,
        transaction_size: usize,
        search_path: Option<&str>,
    ) -> Result<Arc<Pool>, tokio_postgres::Error> {
        let mut cfg: Config = url.parse()?;
        if let Some(sp) = search_path {
            cfg.options(format!("-c search_path={}", sp));
        }
        let size = size.max(1);
        let transaction_size = transaction_size.max(1);
        let mut slots = Vec::with_capacity(size);
        for _ in 0..size {
            slots.push(RwLock::new(open(&cfg).await?));
        }
        let mut tx_slots = Vec::with_capacity(transaction_size);
        for _ in 0..transaction_size {
            tx_slots.push(TxSlot {
                client: RwLock::new(open(&cfg).await?),
                lock: Arc::new(tokio::sync::Mutex::new(())),
            });
        }
        let pool = Arc::new(Pool {
            slots,
            next: AtomicUsize::new(0),
            tx_slots,
            next_tx: AtomicUsize::new(0),
            tenant_locks: std::sync::Mutex::new(std::collections::HashMap::new()),
            cfg: cfg.clone(),
            #[cfg(test)]
            queries: AtomicUsize::new(0),
        });
        for i in 0..(size + transaction_size) {
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
            let closed = if idx < self.slots.len() {
                self.slots[idx]
                    .read()
                    .map(|c| c.is_closed())
                    .unwrap_or(true)
            } else {
                self.tx_slots[idx - self.slots.len()]
                    .client
                    .read()
                    .map(|c| c.is_closed())
                    .unwrap_or(true)
            };
            if !closed {
                continue;
            }
            match open(&cfg).await {
                Ok(c) => {
                    let target = if idx < self.slots.len() {
                        &self.slots[idx]
                    } else {
                        &self.tx_slots[idx - self.slots.len()].client
                    };
                    if let Ok(mut w) = target.write() {
                        *w = c;
                    }
                    info!("postgres connection {} re-established", idx);
                    backoff = Duration::from_millis(500);
                }
                Err(e) => {
                    error!(
                        "postgres reconnect {} failed: {} (retrying in {:?})",
                        idx, e, backoff
                    );
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(15));
                }
            }
        }
    }

    /// Take the cluster-wide advisory lock `key`, waiting until it is free. Used to serialise
    /// publication across several API instances that share a database and a zone directory.
    pub async fn advisory_lock(&self, key: i64) -> Result<AdvisoryLock, tokio_postgres::Error> {
        let (client, conn) = self.cfg.connect(NoTls).await?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        client
            .execute("SELECT pg_advisory_lock($1)", &[&key])
            .await?;
        Ok(AdvisoryLock { _client: client })
    }

    /// Number of general-purpose connections currently usable.
    pub fn healthy(&self) -> usize {
        self.slots
            .iter()
            .filter(|s| s.read().map(|c| !c.is_closed()).unwrap_or(false))
            .count()
    }

    /// Number of usable transaction sessions, for readiness and diagnostics.
    pub fn healthy_transactions(&self) -> usize {
        self.tx_slots
            .iter()
            .filter(|slot| slot.client.read().map(|c| !c.is_closed()).unwrap_or(false))
            .count()
    }

    pub fn size(&self) -> usize {
        self.slots.len()
    }

    /// Borrow one healthy connection. The `Arc` keeps it alive even if the
    /// supervisor replaces the slot while a statement is in flight.
    #[cfg(test)]
    pub fn connection(&self) -> Arc<Client> {
        self.pick()
    }

    #[cfg(test)]
    pub fn query_count(&self) -> usize {
        self.queries.load(Ordering::Relaxed)
    }

    fn pick(&self) -> Arc<Client> {
        let n = self.slots.len();
        let start = self.next.fetch_add(1, Ordering::Relaxed);
        for off in 0..n {
            let c = self.slots[(start + off) % n]
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            if !c.is_closed() {
                return c;
            }
        }
        // everything is down: hand out a closed client; the caller gets an
        // error and the supervisors are already reconnecting.
        self.slots[start % n]
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub async fn query(
        &self,
        statement: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<Row>, Error> {
        #[cfg(test)]
        self.queries.fetch_add(1, Ordering::Relaxed);
        let client = self.pick();
        client.query(statement, params).await
    }

    pub async fn query_opt(
        &self,
        statement: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Option<Row>, Error> {
        #[cfg(test)]
        self.queries.fetch_add(1, Ordering::Relaxed);
        let client = self.pick();
        client.query_opt(statement, params).await
    }

    pub async fn query_one(
        &self,
        statement: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Row, Error> {
        #[cfg(test)]
        self.queries.fetch_add(1, Ordering::Relaxed);
        let client = self.pick();
        client.query_one(statement, params).await
    }

    pub async fn execute(
        &self,
        statement: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<u64, Error> {
        #[cfg(test)]
        self.queries.fetch_add(1, Ordering::Relaxed);
        let client = self.pick();
        client.execute(statement, params).await
    }

    pub async fn batch_execute(&self, query: &str) -> Result<(), Error> {
        #[cfg(test)]
        self.queries.fetch_add(1, Ordering::Relaxed);
        let client = self.pick();
        client.batch_execute(query).await
    }

    /// Check out a bounded transaction session. Any transaction a cancelled
    /// request left open on it is rolled back before the session is reused.
    pub async fn begin(&self) -> Result<TxConn, tokio_postgres::Error> {
        self.begin_inner(None).await
    }

    /// Acquire a transaction slot through a FIFO per-tenant gate. This keeps a
    /// burst from one tenant from occupying multiple sessions while unrelated
    /// tenants wait, while retaining the global bound on database sessions.
    pub async fn begin_for(&self, tenant_id: &str) -> Result<TxConn, tokio_postgres::Error> {
        let tenant_lock = {
            let mut locks = self.tenant_locks.lock().unwrap_or_else(|e| e.into_inner());
            locks.retain(|_, lock| lock.strong_count() > 0);
            locks
                .entry(tenant_id.to_owned())
                .or_default()
                .upgrade()
                .unwrap_or_else(|| {
                    let lock = Arc::new(tokio::sync::Mutex::new(()));
                    locks.insert(tenant_id.to_owned(), Arc::downgrade(&lock));
                    lock
                })
        };
        let tenant_guard = tenant_lock.lock_owned().await;
        self.begin_inner(Some(tenant_guard)).await
    }

    async fn begin_inner(
        &self,
        tenant_guard: Option<tokio::sync::OwnedMutexGuard<()>>,
    ) -> Result<TxConn, tokio_postgres::Error> {
        let idx = self.next_tx.fetch_add(1, Ordering::Relaxed) % self.tx_slots.len();
        let slot = &self.tx_slots[idx];
        let guard = slot.lock.clone().lock_owned().await;
        let client = slot
            .client
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let _ = client.batch_execute("ROLLBACK").await;
        Ok(TxConn {
            _guard: guard,
            _tenant_guard: tenant_guard,
            client,
        })
    }

    /// Execute a complete serializable transaction, retrying only PostgreSQL
    /// serialization failures and deadlocks. The operation closure is rerun,
    /// so callers must keep non-database side effects outside it. Attempts are
    /// bounded and every failed attempt is rolled back before releasing its
    /// session to another request.
    pub async fn run_transaction<T, F, Fut>(
        &self,
        max_attempts: usize,
        mut operation: F,
    ) -> Result<T, tokio_postgres::Error>
    where
        F: FnMut(Arc<Client>) -> Fut,
        Fut: std::future::Future<Output = Result<T, tokio_postgres::Error>>,
    {
        let attempts = max_attempts.max(1);
        for attempt in 0..attempts {
            let tx = self.begin().await?;
            let client = tx.client.clone();
            client
                .batch_execute("BEGIN ISOLATION LEVEL SERIALIZABLE")
                .await?;

            match operation(client.clone()).await {
                Ok(value) => match client.batch_execute("COMMIT").await {
                    Ok(()) => return Ok(value),
                    Err(error) if retryable_transaction_error(&error) && attempt + 1 < attempts => {
                        rollback(&client).await;
                        sleep(transaction_retry_delay(attempt)).await;
                    }
                    Err(error) => {
                        rollback(&client).await;
                        return Err(error);
                    }
                },
                Err(error) if retryable_transaction_error(&error) && attempt + 1 < attempts => {
                    rollback(&client).await;
                    sleep(transaction_retry_delay(attempt)).await;
                }
                Err(error) => {
                    rollback(&client).await;
                    return Err(error);
                }
            }
        }
        unreachable!("bounded transaction loop always returns")
    }
}

async fn rollback(client: &Client) {
    let failed = client.batch_execute("ROLLBACK").await.is_err();
    super::metrics::record_transaction_rollback(failed);
}

fn retryable_transaction_error(error: &tokio_postgres::Error) -> bool {
    error.code().is_some_and(|code| {
        code == &tokio_postgres::error::SqlState::T_R_SERIALIZATION_FAILURE
            || code == &tokio_postgres::error::SqlState::T_R_DEADLOCK_DETECTED
    })
}

fn transaction_retry_delay(attempt: usize) -> Duration {
    Duration::from_millis(10_u64.saturating_mul(1_u64 << attempt.min(5)))
}
