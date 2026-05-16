//! Per-peer reputation tracking + token-bucket rate limiting (spec §6.9).
//!
//! Spec §6.9: "Each node decides whose messages it propagates ... A node
//! tracks per-peer behavior — message rates, signature failures, malformed
//! payloads, hint accuracy. Misbehaving peers get connections refused,
//! asks ignored, peer-exchange entries dropped. Each node does this
//! independently; there is no shared reputation system (those get gamed)
//! and no global blocklist (those get politicized)."
//!
//! Local-only. Never on the wire. Lives alongside `PeerTable` (`peers.rs`)
//! and `Mailbox` (`forward.rs`) — the other local-only state modules.
//!
//! Phase-1 anti-spam Tier 1 scope:
//!   - Per-peer envelope token bucket (default: 100 tokens, refill 10/s)
//!   - Per-peer counters: total seen, signature failures, malformed payloads
//!   - Refuse policy: when sig_failures ≥ `MAX_SIG_FAILURES` OR
//!     malformed_payloads ≥ `MAX_MALFORMED`, the peer is hard-refused
//!     (envelopes dropped before any per-envelope work).
//!
//! Out of scope (Phase 1.5+ work):
//!   - Web-of-trust gossip filter (needs follow graph)
//!   - Per-source IP rate limit at the QUIC transport layer
//!   - Hint-accuracy tracking (storage layer feedback)
//!   - Connection-refused enforcement at handshake time
//!
//! The receive path calls `ReputationTable::observe_envelope(peer)`
//! BEFORE doing any expensive work; if the call returns `false`, the
//! envelope is silently dropped with a `debug!` log line.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::Mutex;

/// Default bucket capacity per peer. A burst of up to this many envelopes
/// is allowed without rate-limiting; beyond that, the peer must wait for
/// refill at `DEFAULT_REFILL_PER_SEC`.
pub const DEFAULT_BUCKET_CAPACITY: u32 = 100;

/// Default token refill rate per second. 10/s = 600/minute steady-state.
pub const DEFAULT_REFILL_PER_SEC: u32 = 10;

/// Signature-failure count at which a peer is hard-refused. Honest peers
/// don't produce malformed signatures.
pub const MAX_SIG_FAILURES: u32 = 10;

/// Malformed-payload count at which a peer is hard-refused. Honest peers
/// don't ship malformed payloads.
pub const MAX_MALFORMED: u32 = 25;

/// Per-peer counters + token-bucket state. All counters are saturating
/// (`u32::MAX`-bounded); a buggy peer doesn't wrap our integers.
///
/// Not `Eq` because `tokens` is `f64` for fractional refill; use field-
/// level comparison if you need to compare snapshots in tests.
#[derive(Debug, Clone, PartialEq)]
pub struct PeerReputation {
    /// Total envelopes observed from this peer (including rejected ones).
    pub envelopes_seen: u32,
    /// Signature verification failures observed.
    pub sig_failures: u32,
    /// Payload decode failures (malformed CBOR / bad field lengths).
    pub malformed_payloads: u32,
    /// Times this peer was rate-limited at the bucket layer.
    pub rate_limit_hits: u32,
    /// Unix-seconds of last activity.
    pub last_seen_at: u64,
    /// Unix-seconds of last misbehavior (sig failure or malformed payload).
    /// `None` if no misbehavior seen yet.
    pub last_misbehavior_at: Option<u64>,
    /// Tokens remaining in the bucket (floating to handle fractional refill).
    pub tokens: f64,
    /// Unix-seconds of last bucket refill calculation.
    pub last_refill_at: u64,
    /// True iff this peer has crossed a refuse threshold and is hard-blocked.
    pub refused: bool,
}

impl PeerReputation {
    fn fresh(now: u64, capacity: u32) -> Self {
        Self {
            envelopes_seen: 0,
            sig_failures: 0,
            malformed_payloads: 0,
            rate_limit_hits: 0,
            last_seen_at: now,
            last_misbehavior_at: None,
            tokens: f64::from(capacity),
            last_refill_at: now,
            refused: false,
        }
    }
}

/// Configuration for a [`ReputationTable`]'s rate limit + refuse thresholds.
#[derive(Debug, Clone, Copy)]
pub struct ReputationPolicy {
    pub bucket_capacity: u32,
    pub refill_per_sec: u32,
    pub max_sig_failures: u32,
    pub max_malformed: u32,
}

impl Default for ReputationPolicy {
    fn default() -> Self {
        Self {
            bucket_capacity: DEFAULT_BUCKET_CAPACITY,
            refill_per_sec: DEFAULT_REFILL_PER_SEC,
            max_sig_failures: MAX_SIG_FAILURES,
            max_malformed: MAX_MALFORMED,
        }
    }
}

/// Async-friendly per-peer reputation directory. Clone-cheap (Arc-wrapped).
#[derive(Clone)]
pub struct ReputationTable {
    inner: Arc<Mutex<HashMap<[u8; 32], PeerReputation>>>,
    policy: ReputationPolicy,
}

impl ReputationTable {
    pub fn new(policy: ReputationPolicy) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            policy,
        }
    }

    /// Record an inbound envelope from `peer` at `now` (unix seconds) and
    /// return `true` if it should be processed, `false` if it should be
    /// dropped at the gate. Increments `envelopes_seen` regardless;
    /// dropped envelopes also bump `rate_limit_hits` (if rate-limited)
    /// or `refused` is already true.
    pub async fn observe_envelope(&self, peer: &[u8; 32], now: u64) -> bool {
        let mut g = self.inner.lock().await;
        let rep = g
            .entry(*peer)
            .or_insert_with(|| PeerReputation::fresh(now, self.policy.bucket_capacity));

        rep.envelopes_seen = rep.envelopes_seen.saturating_add(1);
        rep.last_seen_at = now;

        if rep.refused {
            return false;
        }

        // Refill tokens since last observation.
        if now > rep.last_refill_at {
            let elapsed_secs = (now - rep.last_refill_at) as f64;
            rep.tokens = (rep.tokens + elapsed_secs * f64::from(self.policy.refill_per_sec))
                .min(f64::from(self.policy.bucket_capacity));
            rep.last_refill_at = now;
        }

        if rep.tokens >= 1.0 {
            rep.tokens -= 1.0;
            true
        } else {
            rep.rate_limit_hits = rep.rate_limit_hits.saturating_add(1);
            false
        }
    }

    /// Increment the signature-failure counter for `peer`. If this crosses
    /// the refuse threshold, the peer is marked `refused`. Returns true if
    /// the peer is now refused (newly or already).
    pub async fn record_sig_failure(&self, peer: &[u8; 32], now: u64) -> bool {
        let mut g = self.inner.lock().await;
        let rep = g
            .entry(*peer)
            .or_insert_with(|| PeerReputation::fresh(now, self.policy.bucket_capacity));
        rep.sig_failures = rep.sig_failures.saturating_add(1);
        rep.last_misbehavior_at = Some(now);
        if rep.sig_failures >= self.policy.max_sig_failures {
            rep.refused = true;
        }
        rep.refused
    }

    /// Increment the malformed-payload counter for `peer`. Returns true
    /// if the peer is now refused.
    pub async fn record_malformed(&self, peer: &[u8; 32], now: u64) -> bool {
        let mut g = self.inner.lock().await;
        let rep = g
            .entry(*peer)
            .or_insert_with(|| PeerReputation::fresh(now, self.policy.bucket_capacity));
        rep.malformed_payloads = rep.malformed_payloads.saturating_add(1);
        rep.last_misbehavior_at = Some(now);
        if rep.malformed_payloads >= self.policy.max_malformed {
            rep.refused = true;
        }
        rep.refused
    }

    /// Snapshot the current state for a peer.
    pub async fn get(&self, peer: &[u8; 32]) -> Option<PeerReputation> {
        self.inner.lock().await.get(peer).cloned()
    }

    /// Manually mark a peer as refused (e.g. for operator action).
    pub async fn refuse(&self, peer: &[u8; 32], now: u64) {
        let mut g = self.inner.lock().await;
        let rep = g
            .entry(*peer)
            .or_insert_with(|| PeerReputation::fresh(now, self.policy.bucket_capacity));
        rep.refused = true;
    }

    /// Clear the refuse flag + reset misbehavior counters for a peer.
    pub async fn reinstate(&self, peer: &[u8; 32]) {
        let mut g = self.inner.lock().await;
        if let Some(rep) = g.get_mut(peer) {
            rep.refused = false;
            rep.sig_failures = 0;
            rep.malformed_payloads = 0;
            rep.last_misbehavior_at = None;
        }
    }

    /// True iff the peer is currently refused.
    pub async fn is_refused(&self, peer: &[u8; 32]) -> bool {
        self.inner.lock().await.get(peer).is_some_and(|r| r.refused)
    }

    /// Number of peers tracked.
    pub async fn len(&self) -> usize {
        self.inner.lock().await.len()
    }

    /// True iff no peers have been observed yet.
    pub async fn is_empty(&self) -> bool {
        self.inner.lock().await.is_empty()
    }

    /// Total inbound envelopes counted across all peers (saturating sum).
    pub async fn total_envelopes_seen(&self) -> u64 {
        let g = self.inner.lock().await;
        g.values().map(|r| u64::from(r.envelopes_seen)).sum()
    }
}

impl Default for ReputationTable {
    fn default() -> Self {
        Self::new(ReputationPolicy::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_policy() -> ReputationPolicy {
        ReputationPolicy {
            bucket_capacity: 3,
            refill_per_sec: 1,
            max_sig_failures: 2,
            max_malformed: 2,
        }
    }

    #[tokio::test]
    async fn token_bucket_allows_within_capacity() {
        let t = ReputationTable::new(fixed_policy());
        let peer = [0xAA; 32];
        assert!(t.observe_envelope(&peer, 1).await);
        assert!(t.observe_envelope(&peer, 1).await);
        assert!(t.observe_envelope(&peer, 1).await);
        // Fourth in the same second exceeds the bucket.
        assert!(!t.observe_envelope(&peer, 1).await);
        let snap = t.get(&peer).await.unwrap();
        assert_eq!(snap.rate_limit_hits, 1);
        assert_eq!(snap.envelopes_seen, 4);
    }

    #[tokio::test]
    async fn token_bucket_refills_over_time() {
        let t = ReputationTable::new(fixed_policy());
        let peer = [0xBB; 32];
        // Drain the bucket.
        for _ in 0..3 {
            assert!(t.observe_envelope(&peer, 100).await);
        }
        assert!(!t.observe_envelope(&peer, 100).await);
        // Two seconds later → +2 tokens → next two allowed.
        assert!(t.observe_envelope(&peer, 102).await);
        assert!(t.observe_envelope(&peer, 102).await);
        // Bucket is now drained again.
        assert!(!t.observe_envelope(&peer, 102).await);
    }

    #[tokio::test]
    async fn sig_failures_lead_to_refusal() {
        let t = ReputationTable::new(fixed_policy());
        let peer = [0xCC; 32];
        assert!(!t.is_refused(&peer).await);
        assert!(!t.record_sig_failure(&peer, 1).await); // 1/2
        assert!(t.record_sig_failure(&peer, 2).await); // 2/2 → refused
        assert!(t.is_refused(&peer).await);
        // Subsequent envelopes are dropped at the gate even with full
        // bucket.
        assert!(!t.observe_envelope(&peer, 3).await);
    }

    #[tokio::test]
    async fn malformed_payloads_lead_to_refusal() {
        let t = ReputationTable::new(fixed_policy());
        let peer = [0xDD; 32];
        assert!(!t.record_malformed(&peer, 10).await);
        assert!(t.record_malformed(&peer, 11).await);
        let snap = t.get(&peer).await.unwrap();
        assert_eq!(snap.malformed_payloads, 2);
        assert!(snap.refused);
    }

    #[tokio::test]
    async fn reinstate_clears_refusal() {
        let t = ReputationTable::new(fixed_policy());
        let peer = [0xEE; 32];
        t.record_sig_failure(&peer, 1).await;
        t.record_sig_failure(&peer, 2).await;
        assert!(t.is_refused(&peer).await);
        t.reinstate(&peer).await;
        assert!(!t.is_refused(&peer).await);
        let snap = t.get(&peer).await.unwrap();
        assert_eq!(snap.sig_failures, 0);
    }

    #[tokio::test]
    async fn manual_refuse_works() {
        let t = ReputationTable::new(fixed_policy());
        let peer = [0xFF; 32];
        t.refuse(&peer, 1).await;
        assert!(t.is_refused(&peer).await);
        assert!(!t.observe_envelope(&peer, 2).await);
    }
}
