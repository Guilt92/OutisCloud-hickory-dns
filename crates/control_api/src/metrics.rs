//! Prometheus gauges for publication health (exposed on /metrics).
use crate::dns_manager::LastPublish;
use once_cell::sync::Lazy;
use prometheus::{IntCounter, IntGauge, register_int_counter, register_int_gauge};

static ZONE_SNAPSHOT_FAILURES: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "outis_zone_snapshot_failures_total",
        "failed zone revision snapshot attempts"
    )
    .unwrap()
});

static ZONES_PUBLISHED: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!("outis_zones_published", "zones published in the last run").unwrap()
});
static ZONES_FAILED: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!("outis_zones_failed", "zones that failed in the last run").unwrap()
});
static LAST_RUN: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "outis_last_publish_timestamp_seconds",
        "unix time of the last publication run"
    )
    .unwrap()
});
static LAST_OK: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "outis_last_publish_ok",
        "1 if the last publication run had no failures"
    )
    .unwrap()
});
static BUNDLE_VERSION: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!("outis_bundle_version", "current agent bundle version").unwrap()
});
static AGENTS_BEHIND: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "outis_agents_out_of_sync",
        "enabled agents whose applied version is behind"
    )
    .unwrap()
});
static DB_HEALTHY: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "outis_db_connections_healthy",
        "usable PostgreSQL connections"
    )
    .unwrap()
});

pub fn record_publish(l: &LastPublish) {
    ZONES_PUBLISHED.set(l.published as i64);
    ZONES_FAILED.set(l.failed.len() as i64);
    LAST_RUN.set(l.at.timestamp());
    LAST_OK.set(if l.failed.is_empty() && l.error.is_none() {
        1
    } else {
        0
    });
}

pub fn record_sync(version: i64, behind: i64, db_healthy: usize) {
    BUNDLE_VERSION.set(version);
    AGENTS_BEHIND.set(behind);
    DB_HEALTHY.set(db_healthy as i64);
}

pub fn record_snapshot_failure() {
    ZONE_SNAPSHOT_FAILURES.inc();
}

/// Make sure all gauges exist (so they are scraped with value 0 before the first run).
pub fn init() {
    Lazy::force(&ZONES_PUBLISHED);
    Lazy::force(&ZONES_FAILED);
    Lazy::force(&LAST_RUN);
    Lazy::force(&LAST_OK);
    Lazy::force(&BUNDLE_VERSION);
    Lazy::force(&AGENTS_BEHIND);
    Lazy::force(&DB_HEALTHY);
    Lazy::force(&ZONE_SNAPSHOT_FAILURES);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_failures_are_exposed_in_metrics() {
        init();
        let before = ZONE_SNAPSHOT_FAILURES.get();
        record_snapshot_failure();
        assert_eq!(ZONE_SNAPSHOT_FAILURES.get(), before + 1);
        assert!(
            prometheus::gather()
                .iter()
                .any(|family| family.get_name() == "outis_zone_snapshot_failures_total")
        );
    }
}
