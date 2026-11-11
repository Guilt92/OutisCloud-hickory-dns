//! A request handler whose catalog can be replaced while the server is
//! running (hot reload), with optional per-source rate limiting.

use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};

use crate::net::runtime::Time;
use crate::proto::op::{Header, ResponseCode};
use crate::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use crate::zone_handler::Catalog;

/// Per-source query budget. IPv4 sources are counted per address, IPv6
/// sources per /64 (a single subscriber commonly owns a whole /64).
#[derive(Clone, Copy, Debug)]
pub struct RateLimitConfig {
    pub queries_per_second: u32,
    pub burst: u32,
}

fn limiter_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => match v4.to_ipv6_mapped().to_ipv4_mapped() {
            Some(v) => IpAddr::V4(v),
            None => IpAddr::V4(v4),
        },
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return IpAddr::V4(v4);
            }
            let mut seg = v6.segments();
            for s in seg.iter_mut().skip(4) {
                *s = 0;
            }
            IpAddr::V6(seg.into())
        }
    }
}

struct Shared {
    catalog: RwLock<Arc<Catalog>>,
    limiter: Option<DefaultKeyedRateLimiter<IpAddr>>,
    limited: AtomicU64,
    reloads: AtomicU64,
}

/// Cheap to clone; all clones share the same catalog and limiter.
#[derive(Clone)]
pub struct SwapHandler {
    shared: Arc<Shared>,
}

impl SwapHandler {
    pub fn new(catalog: Catalog, limit: Option<RateLimitConfig>) -> Self {
        let limiter = limit.and_then(|l| {
            let qps = NonZeroU32::new(l.queries_per_second)?;
            let burst = NonZeroU32::new(l.burst.max(l.queries_per_second))?;
            Some(RateLimiter::keyed(Quota::per_second(qps).allow_burst(burst)))
        });
        Self {
            shared: Arc::new(Shared {
                catalog: RwLock::new(Arc::new(catalog)),
                limiter,
                limited: AtomicU64::new(0),
                reloads: AtomicU64::new(0),
            }),
        }
    }

    /// Atomically replace the catalog. Requests already being served finish on
    /// the catalog they started with.
    pub fn swap(&self, catalog: Catalog) {
        *self.shared.catalog.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(catalog);
        self.shared.reloads.fetch_add(1, Ordering::Relaxed);
    }

    /// Number of queries dropped by the rate limiter so far.
    pub fn rate_limited(&self) -> u64 {
        self.shared.limited.load(Ordering::Relaxed)
    }

    /// Number of successful hot reloads so far.
    pub fn reloads(&self) -> u64 {
        self.shared.reloads.load(Ordering::Relaxed)
    }

    fn current(&self) -> Arc<Catalog> {
        self.shared.catalog.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Bound the limiter's memory (called opportunistically).
    fn allow(&self, ip: IpAddr) -> bool {
        match &self.shared.limiter {
            None => true,
            Some(l) => {
                if l.len() > 100_000 {
                    l.retain_recent();
                    l.shrink_to_fit();
                }
                l.check_key(&limiter_key(ip)).is_ok()
            }
        }
    }
}

#[async_trait::async_trait]
impl RequestHandler for SwapHandler {
    async fn handle_request<R: ResponseHandler, T: Time>(
        &self,
        request: &Request,
        response_handle: R,
    ) -> ResponseInfo {
        if !self.allow(request.src().ip()) {
            // Over budget: drop without answering. Replying (even REFUSED)
            // would let spoofed-source floods reflect traffic at the victim.
            self.shared.limited.fetch_add(1, Ordering::Relaxed);
            let mut header = Header::response_from_request(request.header());
            header.set_response_code(ResponseCode::Refused);
            return ResponseInfo::from(header);
        }
        self.current().handle_request::<R, T>(request, response_handle).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_sources_share_a_budget_per_slash_64() {
        let a = limiter_key("2001:db8:1:2:aaaa::1".parse().unwrap());
        let b = limiter_key("2001:db8:1:2:bbbb::9".parse().unwrap());
        let c = limiter_key("2001:db8:1:3::1".parse().unwrap());
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(limiter_key("::ffff:192.0.2.1".parse().unwrap()), "192.0.2.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn limiter_enforces_burst_then_blocks_per_source() {
        let h = SwapHandler::new(Catalog::new(), Some(RateLimitConfig { queries_per_second: 1, burst: 5 }));
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        let b: IpAddr = "192.0.2.2".parse().unwrap();
        let allowed = (0..20).filter(|_| h.allow(a)).count();
        assert!((5..=6).contains(&allowed), "burst of 5 (+ at most one refill): {allowed}");
        assert!(h.allow(b), "other sources are unaffected");
        let off = SwapHandler::new(Catalog::new(), None);
        assert!((0..1000).all(|_| off.allow(a)), "no limiter configured");
    }

    #[test]
    fn swap_replaces_the_catalog() {
        let h = SwapHandler::new(Catalog::new(), None);
        let before = Arc::as_ptr(&h.current());
        h.swap(Catalog::new());
        assert_ne!(before, Arc::as_ptr(&h.current()));
        assert_eq!(h.reloads(), 1);
    }
}
