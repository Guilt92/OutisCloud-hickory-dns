use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::{SystemTime, UNIX_EPOCH};

/// Shared serving readiness state for the DNS process.
///
/// `/health` only proves that the HTTP listener is alive. `/ready` additionally
/// requires that listeners were configured, the catalog loaded and the latest
/// publication/reload succeeded within the freshness window.
#[derive(Clone, Default)]
pub(crate) struct Readiness {
    inner: Arc<Inner>,
}

#[derive(Default)]
struct Inner {
    ready: AtomicBool,
    last_success_unix_secs: AtomicU64,
}

impl Readiness {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn mark_ready(&self) {
        self.inner.ready.store(true, Ordering::SeqCst);
        self.inner
            .last_success_unix_secs
            .store(now_secs(), Ordering::SeqCst);
    }

    pub(crate) fn mark_not_ready(&self) {
        self.inner.ready.store(false, Ordering::SeqCst);
    }

    pub(crate) fn is_ready(&self, max_age_secs: u64) -> bool {
        if !self.inner.ready.load(Ordering::SeqCst) {
            return false;
        }
        let last = self.inner.last_success_unix_secs.load(Ordering::SeqCst);
        if last == 0 {
            return false;
        }
        now_secs().saturating_sub(last) <= max_age_secs
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readiness_requires_explicit_mark_and_expires() {
        let r = Readiness::new();
        assert!(!r.is_ready(300));
        r.mark_ready();
        assert!(r.is_ready(300));
        std::thread::sleep(std::time::Duration::from_secs(1));
        assert!(!r.is_ready(0));
        r.mark_not_ready();
        assert!(!r.is_ready(300));
    }
}
