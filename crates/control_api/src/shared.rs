//! Coordination between several API replicas through the one thing they already share: PostgreSQL.
//!
//! * [`hit`] — fixed-window rate limiting. One atomic `INSERT .. ON CONFLICT DO UPDATE .. RETURNING`
//!   per request on the *database* clock, so two replicas can never both read "9 of 10" and both
//!   allow the 10th, switching replicas does not reset a budget and a replica restart loses nothing.
//! * [`try_lease`] — single-writer lease for the analytics collector (see `tenants::spawn_collector`).
//!
//! If the database cannot be reached the callers fall back to their in-process limiter (stricter per
//! replica, never fail-open) and log a warning.

use super::*;

pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS shared_rate_limits (
    bucket TEXT NOT NULL,
    window_start TIMESTAMPTZ NOT NULL,
    hits INTEGER NOT NULL,
    PRIMARY KEY (bucket, window_start)
);
CREATE INDEX IF NOT EXISTS idx_shared_rate_limits_window ON shared_rate_limits(window_start);
CREATE TABLE IF NOT EXISTS collector_lease (
    name TEXT PRIMARY KEY,
    holder TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS collector_state (
    name TEXT PRIMARY KEY,
    payload JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
";

/// Count one event in `bucket`'s current `window_secs` window. `Ok(None)` = allowed,
/// `Ok(Some(retry_after_secs))` = over `limit`.
pub async fn hit(
    db: &Pool,
    bucket: &str,
    limit: u32,
    window_secs: i64,
) -> Result<Option<u64>, tokio_postgres::Error> {
    let w = window_secs.max(1) as f64;
    let row = db.query_one(
        "INSERT INTO shared_rate_limits (bucket, window_start, hits) \
         VALUES ($1, to_timestamp(floor(extract(epoch from now()) / $2::double precision) * $2::double precision), 1) \
         ON CONFLICT (bucket, window_start) DO UPDATE SET hits = shared_rate_limits.hits + 1 \
         RETURNING hits, GREATEST(1, ceil(extract(epoch from (window_start + make_interval(secs => $2::double precision) - now()))))::bigint",
        &[&bucket, &w]).await?;
    let (hits, retry): (i32, i64) = (row.get(0), row.get(1));
    Ok(if hits as u32 > limit {
        Some(retry as u64)
    } else {
        None
    })
}

/// Delete expired windows (cheap, idempotent; every replica may run it).
pub async fn purge_rate_limits(db: &Pool) -> Result<u64, tokio_postgres::Error> {
    db.execute(
        "DELETE FROM shared_rate_limits WHERE window_start < now() - interval '15 minutes'",
        &[],
    )
    .await
}

/// Housekeeping independent of the analytics collector: expired rate-limit
/// windows must be removed even when sampling is disabled on every replica.
pub fn spawn_rate_limit_cleanup(db: Arc<Pool>) {
    tokio::spawn(async move {
        loop {
            match purge_rate_limits(&db).await {
                Ok(n) if n > 0 => log::debug!("rate-limit cleanup removed {} expired windows", n),
                Ok(_) => {}
                Err(e) => warn!("rate-limit cleanup: {}", full_error_string(&e)),
            }
            tokio::time::sleep(std::time::Duration::from_secs(5 * 60)).await;
        }
    });
}

/// Acquire or renew the lease `name` for `holder`. Atomic; an expired lease is taken over by the first caller.
pub async fn try_lease(
    db: &Pool,
    name: &str,
    holder: &str,
    ttl_secs: f64,
) -> Result<bool, tokio_postgres::Error> {
    let r = db.query_opt(
        "INSERT INTO collector_lease (name, holder, expires_at) VALUES ($1, $2, now() + make_interval(secs => $3::double precision)) \
         ON CONFLICT (name) DO UPDATE SET holder = EXCLUDED.holder, expires_at = EXCLUDED.expires_at \
         WHERE collector_lease.holder = EXCLUDED.holder OR collector_lease.expires_at < now() RETURNING holder",
        &[&name, &holder, &ttl_secs]).await?;
    Ok(r.is_some())
}

/// Shared-budget check with local fallback. `Some(wait)` = refuse.
pub async fn limited(
    db: &Pool,
    bucket: &str,
    limit: u32,
    window_secs: i64,
    local: impl FnOnce() -> bool,
) -> Option<u64> {
    match hit(db, bucket, limit, window_secs).await {
        Ok(v) => v,
        Err(e) => {
            warn!(
                "shared rate limit unavailable ({}), using the per-replica limiter",
                full_error_string(&e)
            );
            if local() {
                None
            } else {
                Some(window_secs.max(1) as u64)
            }
        }
    }
}
