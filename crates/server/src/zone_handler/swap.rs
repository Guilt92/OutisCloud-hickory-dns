//! A request handler whose catalog can be replaced while the server is
//! running (hot reload), with optional per-source rate limiting.

use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};

use crate::net::runtime::Time;
use crate::net::xfer::Protocol;
use crate::proto::op::{Header, ResponseCode};
use crate::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use crate::zone_handler::{Catalog, MessageResponseBuilder};

/// Per-source query budget. IPv4 sources are counted per address, IPv6
/// sources per /64 (a single subscriber commonly owns a whole /64).
#[derive(Clone, Copy, Debug)]
pub struct RateLimitConfig {
    pub queries_per_second: u32,
    pub burst: u32,
    /// Response Rate Limiting "slip": every `slip`-th over-budget UDP query is answered with an
    /// empty truncated (TC=1) response instead of being dropped, so a legitimate client that
    /// shares a (spoofed) address with a flood retries over TCP and still gets an answer, while
    /// the small response gives a reflection attacker no amplification. 0 = always drop,
    /// 1 = always truncate. Queries over TCP are never rate limited: the handshake proves the
    /// source address.
    pub slip: u32,
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
    slipped: AtomicU64,
    slip: u32,
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
            Some(RateLimiter::keyed(
                Quota::per_second(qps).allow_burst(burst),
            ))
        });
        Self {
            shared: Arc::new(Shared {
                catalog: RwLock::new(Arc::new(catalog)),
                limiter,
                limited: AtomicU64::new(0),
                slipped: AtomicU64::new(0),
                slip: limit.map(|l| l.slip).unwrap_or(0),
                reloads: AtomicU64::new(0),
            }),
        }
    }

    /// Atomically replace the catalog. Requests already being served finish on
    /// the catalog they started with.
    pub fn swap(&self, catalog: Catalog) {
        *self
            .shared
            .catalog
            .write()
            .unwrap_or_else(|e| e.into_inner()) = Arc::new(catalog);
        self.shared.reloads.fetch_add(1, Ordering::Relaxed);
    }

    /// Number of queries dropped by the rate limiter so far.
    pub fn rate_limited(&self) -> u64 {
        self.shared.limited.load(Ordering::Relaxed)
    }

    /// Number of over-budget queries answered with a truncated response (slip).
    pub fn slipped(&self) -> u64 {
        self.shared.slipped.load(Ordering::Relaxed)
    }

    /// Number of successful hot reloads so far.
    pub fn reloads(&self) -> u64 {
        self.shared.reloads.load(Ordering::Relaxed)
    }

    fn current(&self) -> Arc<Catalog> {
        self.shared
            .catalog
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
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
        if request.protocol() != Protocol::Tcp && !self.allow(request.src().ip()) {
            // Over budget. Replying with a full answer (or even REFUSED) would let spoofed-source
            // floods reflect traffic at the victim, so the query is dropped, except for the
            // occasional tiny TC=1 "slip" that lets a real client retry over TCP.
            let n = self.shared.limited.fetch_add(1, Ordering::Relaxed) + 1;
            let mut header = Header::response_from_request(request.header());
            let slip = self.shared.slip;
            if slip > 0 && request.protocol() == Protocol::Udp && n % u64::from(slip) == 0 {
                self.shared.slipped.fetch_add(1, Ordering::Relaxed);
                header.set_truncated(true);
                let response = MessageResponseBuilder::new(request.raw_queries(), None)
                    .build_no_records(header);
                let mut response_handle = response_handle;
                return match response_handle.send_response(response).await {
                    Ok(info) => info,
                    Err(_) => ResponseInfo::from(header),
                };
            }
            header.set_response_code(ResponseCode::Refused);
            return ResponseInfo::from(header);
        }
        self.current()
            .handle_request::<R, T>(request, response_handle)
            .await
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
        assert_eq!(
            limiter_key("::ffff:192.0.2.1".parse().unwrap()),
            "192.0.2.1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn limiter_enforces_burst_then_blocks_per_source() {
        let h = SwapHandler::new(
            Catalog::new(),
            Some(RateLimitConfig {
                queries_per_second: 1,
                burst: 5,
                slip: 0,
            }),
        );
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        let b: IpAddr = "192.0.2.2".parse().unwrap();
        let allowed = (0..20).filter(|_| h.allow(a)).count();
        assert!(
            (5..=6).contains(&allowed),
            "burst of 5 (+ at most one refill): {allowed}"
        );
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
