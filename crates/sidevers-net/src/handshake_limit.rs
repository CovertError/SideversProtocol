//! Phase 1.D: per-source-IP handshake rate limit (spec §4.6).
//!
//! The handshake itself does ~3KB of work + an X25519 + several signature
//! ops; a misbehaving source can exhaust CPU + entropy by hammering open
//! connections that never finish. §4.6 SHOULD-recommends per-source
//! rate-limiting; this module is the implementation.
//!
//! Token bucket per remote IP. Capacity 8 connections (occasional bursts
//! from a single client are fine), refill 2 per second (sustained ~120
//! per minute is well over anything a legitimate peer needs). Sliding
//! eviction keeps the table bounded.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::Mutex;

/// Default bucket capacity. A peer can burst up to 8 fresh handshake
/// attempts at once before being throttled.
pub const HANDSHAKE_BURST: f64 = 8.0;

/// Default refill rate per second.
pub const HANDSHAKE_REFILL_PER_SEC: f64 = 2.0;

/// Idle-window after which an IP's entry is forgotten so the table
/// doesn't grow without bound. Generous so well-behaved sources don't
/// get re-bursted artificially.
pub const HANDSHAKE_IDLE_FORGET_SECS: f64 = 3_600.0;

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    last_refill_at: f64,
}

#[derive(Debug, Clone)]
pub struct HandshakeLimiter {
    inner: Arc<Mutex<HashMap<IpAddr, Bucket>>>,
    burst: f64,
    refill_per_sec: f64,
}

impl HandshakeLimiter {
    pub fn new(burst: f64, refill_per_sec: f64) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            burst: burst.max(1.0),
            refill_per_sec: refill_per_sec.max(0.01),
        }
    }

    /// Try to consume one token for `ip`. Returns `true` if accepted
    /// (handshake may proceed), `false` if throttled (caller should
    /// close the QUIC connection without running the responder
    /// handshake).
    pub async fn try_acquire(&self, ip: IpAddr) -> bool {
        let now = now_secs();
        let mut tab = self.inner.lock().await;

        // Lazy eviction of long-idle entries.
        tab.retain(|_, b| now - b.last_refill_at < HANDSHAKE_IDLE_FORGET_SECS);

        let bucket = tab.entry(ip).or_insert(Bucket {
            tokens: self.burst,
            last_refill_at: now,
        });
        let elapsed = (now - bucket.last_refill_at).max(0.0);
        bucket.tokens = (bucket.tokens + elapsed * self.refill_per_sec).min(self.burst);
        bucket.last_refill_at = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Snapshot the bucket state for `ip`, mostly for tests / diagnostics.
    pub async fn tokens(&self, ip: IpAddr) -> Option<f64> {
        let tab = self.inner.lock().await;
        tab.get(&ip).map(|b| b.tokens)
    }

    /// Number of remembered source IPs. Useful for tests + metrics.
    pub async fn tracked(&self) -> usize {
        self.inner.lock().await.len()
    }
}

impl Default for HandshakeLimiter {
    fn default() -> Self {
        Self::new(HANDSHAKE_BURST, HANDSHAKE_REFILL_PER_SEC)
    }
}

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn burst_is_capped() {
        let l = HandshakeLimiter::new(3.0, 0.001); // tiny refill so we observe the cap
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(l.try_acquire(ip).await);
        assert!(l.try_acquire(ip).await);
        assert!(l.try_acquire(ip).await);
        assert!(!l.try_acquire(ip).await, "fourth attempt must be throttled");
    }

    #[tokio::test]
    async fn refill_eventually_allows_more() {
        let l = HandshakeLimiter::new(1.0, 100.0); // very fast refill
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(l.try_acquire(ip).await);
        // Burst is now empty; wait long enough for refill.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(l.try_acquire(ip).await);
    }

    #[tokio::test]
    async fn separate_ips_have_separate_budgets() {
        let l = HandshakeLimiter::new(1.0, 0.001);
        let ip1: IpAddr = "127.0.0.1".parse().unwrap();
        let ip2: IpAddr = "127.0.0.2".parse().unwrap();
        assert!(l.try_acquire(ip1).await);
        assert!(!l.try_acquire(ip1).await);
        // ip2 has its own bucket.
        assert!(l.try_acquire(ip2).await);
    }
}
