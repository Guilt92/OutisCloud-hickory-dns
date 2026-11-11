/// DNS Manager - Handles automatic zone file generation and DNS server reload
/// This is the core of the Option B architecture: control-api manages the database
/// and generates zone files, the DNS server watches those files and reloads automatically
use std::path::Path;
use std::sync::Arc;
use crate::db_pool::Pool;
use crate::zone_file_generator::{self, PublishReport};

#[derive(Debug)]
pub enum DnsManagerError {
    GenerationFailed(String),
    DirectoryError(String),
}

/// Outcome of the most recent publication run (for status endpoints/metrics).
#[derive(Clone, Debug)]
pub struct LastPublish {
    pub at: chrono::DateTime<chrono::Utc>,
    pub published: usize,
    pub failed: Vec<(String, String)>,
    /// set when the whole run failed (database/disk error)
    pub error: Option<String>,
}

pub struct DnsManager {
    config_dir: String,
    last: std::sync::Mutex<Option<LastPublish>>,
    /// Serialises publication runs. Every run reads the database *after*
    /// acquiring this lock, so concurrent writers can neither interleave file
    /// writes nor let an older snapshot overwrite a newer one.
    publish_lock: tokio::sync::Mutex<()>,
}

impl std::error::Error for DnsManagerError {}

impl std::fmt::Display for DnsManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsManagerError::GenerationFailed(msg) => write!(f, "Zone generation failed: {}", msg),
            DnsManagerError::DirectoryError(msg) => write!(f, "Directory error: {}", msg),
        }
    }
}

impl DnsManager {
    pub fn new(config_dir: String) -> Self {
        Self { config_dir, last: std::sync::Mutex::new(None), publish_lock: tokio::sync::Mutex::new(()) }
    }

    /// Regenerate all zone files - called after any zone or record mutation.
    ///
    /// Returns the per-zone report; individual zone failures do not fail the
    /// run (the previous zone file stays published), see [`PublishReport`].
    pub async fn regenerate_zones(&self, db: Arc<Pool>) -> Result<PublishReport, DnsManagerError> {
        let _guard = self.publish_lock.lock().await;
        self.ensure_config_dir_exists()?;
        let res = zone_file_generator::generate_all(&self.config_dir, db).await
            .map_err(|e| DnsManagerError::GenerationFailed(format!("{:#}", e)));
        let entry = match &res {
            Ok(r) => LastPublish { at: chrono::Utc::now(), published: r.published.len(), failed: r.failed.clone(), error: None },
            Err(e) => LastPublish { at: chrono::Utc::now(), published: 0, failed: vec![], error: Some(e.to_string()) },
        };
        crate::metrics::record_publish(&entry);
        if let Ok(mut l) = self.last.lock() { *l = Some(entry); }
        res
    }

    /// Hold the publication lock (readers that need a consistent view of the files).
    pub async fn lock(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.publish_lock.lock().await
    }

    pub fn last_publish(&self) -> Option<LastPublish> {
        self.last.lock().ok().and_then(|l| l.clone())
    }

    fn ensure_config_dir_exists(&self) -> Result<(), DnsManagerError> {
        std::fs::create_dir_all(&self.config_dir)
            .map_err(|e| DnsManagerError::DirectoryError(e.to_string()))?;
        Ok(())
    }

    /// Get the path to the zone directory
    pub fn zone_dir(&self) -> &String {
        &self.config_dir
    }

    /// Get the path to the named.toml config file
    #[allow(dead_code)]
    pub fn named_config_path(&self) -> String {
        format!("{}/named.toml", self.config_dir)
    }

    /// Check if zone files have been generated
    #[allow(dead_code)]
    pub fn is_configured(&self) -> bool {
        Path::new(&self.named_config_path()).exists()
    }
}
