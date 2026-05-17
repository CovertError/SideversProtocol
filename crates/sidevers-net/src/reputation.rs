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
//! Phase 1.5h+ — sybil defense (Audit P1.C):
//!   - `IpSybilTracker` records distinct pubkeys per source IP within a
//!     rolling window. The per-pubkey reputation is sybil-defeatable
//!     because ephemeral sides cost nothing; the per-IP tracker raises
//!     the cost of "spin up N fresh identities from one host" to a
//!     bounded rate (operator-tunable).
//!
//! Out of scope (Phase 2+ work):
//!   - Web-of-trust gossip filter (needs follow graph)
//!   - Hint-accuracy tracking (storage layer feedback)
//!
//! The receive path calls `ReputationTable::observe_envelope(peer)`
//! BEFORE doing any expensive work; if the call returns `false`, the
//! envelope is silently dropped with a `debug!` log line.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
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

// =========================================================================
// Sybil defense — per-IP fresh-identity tracking (Audit P1.C)
// =========================================================================

/// Default window (seconds) over which `IpSybilTracker` counts distinct
/// pubkeys per IP. 1 hour is generous: behind a CGNAT, a few users on the
/// same egress IP rotating sides occasionally won't hit the cap.
pub const SYBIL_WINDOW_SECS: u64 = 3600;

/// Default max distinct pubkeys per IP within `SYBIL_WINDOW_SECS`. An
/// attacker spinning up fresh ephemeral sides from one host exceeds this
/// quickly; a real shared-NAT cohort comfortably fits beneath it.
pub const SYBIL_MAX_NEW_PUBKEYS_PER_IP: usize = 16;

/// State kept per source IP for sybil detection.
#[derive(Debug, Clone)]
pub struct IpSybilState {
    /// Distinct pubkeys observed from this IP within the current window.
    pub pubkeys: HashSet<[u8; 32]>,
    /// Window-start time (unix seconds). When `now - window_start_at`
    /// exceeds `SYBIL_WINDOW_SECS`, the set is cleared on next observe.
    pub window_start_at: u64,
    /// Total times this IP has been over-quota since process start
    /// (saturating). Operator-visible for alerting.
    pub over_quota_count: u32,
}

impl IpSybilState {
    fn fresh(now: u64) -> Self {
        Self {
            pubkeys: HashSet::new(),
            window_start_at: now,
            over_quota_count: 0,
        }
    }
}

/// Policy knobs for `IpSybilTracker`.
#[derive(Debug, Clone, Copy)]
pub struct IpSybilPolicy {
    pub window_secs: u64,
    pub max_new_pubkeys_per_ip: usize,
}

impl Default for IpSybilPolicy {
    fn default() -> Self {
        Self {
            window_secs: SYBIL_WINDOW_SECS,
            max_new_pubkeys_per_ip: SYBIL_MAX_NEW_PUBKEYS_PER_IP,
        }
    }
}

/// Outcome of an `observe(peer, ip)` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SybilDecision {
    /// Allow the connection / envelope through.
    Allow,
    /// This IP has cycled too many distinct pubkeys in the current
    /// window — refuse. Caller drops the connection / envelope without
    /// running further work.
    OverQuota,
}

/// Tracks distinct pubkeys observed per source IP within a rolling
/// window. Designed to be called once per (peer, ip) pair at the
/// connection-accept layer (after the per-IP handshake rate limit but
/// before any per-peer reputation logic).
///
/// **Not yet wired into the accept loop** (Audit P1.C — infrastructure
/// shipping in 1.5h, behavior change deferred so the operational policy
/// can be tuned in a follow-up). Available immediately as a metric
/// source for operators experimenting with thresholds.
#[derive(Clone)]
pub struct IpSybilTracker {
    inner: Arc<Mutex<HashMap<IpAddr, IpSybilState>>>,
    policy: IpSybilPolicy,
}

impl IpSybilTracker {
    pub fn new(policy: IpSybilPolicy) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            policy,
        }
    }

    /// Record that `peer` has been seen from `ip` at `now`. Returns
    /// `Allow` if the IP is within its fresh-identity quota for the
    /// current window, `OverQuota` otherwise.
    pub async fn observe(&self, peer: &[u8; 32], ip: IpAddr, now: u64) -> SybilDecision {
        let mut g = self.inner.lock().await;
        let state = g.entry(ip).or_insert_with(|| IpSybilState::fresh(now));

        // Roll the window if it's expired.
        if now.saturating_sub(state.window_start_at) >= self.policy.window_secs {
            state.pubkeys.clear();
            state.window_start_at = now;
        }

        // Already-known pubkey on this IP is free — only count
        // newly-introduced identities against the quota.
        if state.pubkeys.contains(peer) {
            return SybilDecision::Allow;
        }

        if state.pubkeys.len() >= self.policy.max_new_pubkeys_per_ip {
            state.over_quota_count = state.over_quota_count.saturating_add(1);
            return SybilDecision::OverQuota;
        }

        state.pubkeys.insert(*peer);
        SybilDecision::Allow
    }

    /// Snapshot the state for an IP (for tests and metrics).
    pub async fn get(&self, ip: &IpAddr) -> Option<IpSybilState> {
        self.inner.lock().await.get(ip).cloned()
    }

    /// Number of tracked source IPs.
    pub async fn tracked_ips(&self) -> usize {
        self.inner.lock().await.len()
    }
}

impl Default for IpSybilTracker {
    fn default() -> Self {
        Self::new(IpSybilPolicy::default())
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

    // ---- IpSybilTracker (Audit P1.C) ----

    fn tight_sybil_policy() -> IpSybilPolicy {
        IpSybilPolicy {
            window_secs: 10,
            max_new_pubkeys_per_ip: 3,
        }
    }

    #[tokio::test]
    async fn sybil_tracker_allows_under_quota() {
        let s = IpSybilTracker::new(tight_sybil_policy());
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        for i in 0..3u8 {
            let peer = [i; 32];
            assert_eq!(s.observe(&peer, ip, 100).await, SybilDecision::Allow);
        }
        let state = s.get(&ip).await.unwrap();
        assert_eq!(state.pubkeys.len(), 3);
        assert_eq!(state.over_quota_count, 0);
    }

    #[tokio::test]
    async fn sybil_tracker_refuses_fourth_distinct_pubkey() {
        let s = IpSybilTracker::new(tight_sybil_policy());
        let ip: IpAddr = "10.0.0.2".parse().unwrap();
        for i in 0..3u8 {
            assert_eq!(s.observe(&[i; 32], ip, 100).await, SybilDecision::Allow);
        }
        // Fourth fresh pubkey from the same IP within the window.
        assert_eq!(
            s.observe(&[99u8; 32], ip, 100).await,
            SybilDecision::OverQuota
        );
        let state = s.get(&ip).await.unwrap();
        assert_eq!(state.over_quota_count, 1);
        // The over-quota pubkey is NOT added to the set (so a recovery
        // window doesn't include it).
        assert_eq!(state.pubkeys.len(), 3);
    }

    #[tokio::test]
    async fn sybil_tracker_already_known_pubkey_is_free() {
        let s = IpSybilTracker::new(tight_sybil_policy());
        let ip: IpAddr = "10.0.0.3".parse().unwrap();
        let peer = [0x11; 32];
        assert_eq!(s.observe(&peer, ip, 100).await, SybilDecision::Allow);
        // Re-observe the same pubkey 5 more times within the window —
        // still under quota because we count distinct identities.
        for _ in 0..5 {
            assert_eq!(s.observe(&peer, ip, 100).await, SybilDecision::Allow);
        }
        let state = s.get(&ip).await.unwrap();
        assert_eq!(state.pubkeys.len(), 1);
    }

    #[tokio::test]
    async fn sybil_tracker_resets_after_window() {
        let s = IpSybilTracker::new(tight_sybil_policy());
        let ip: IpAddr = "10.0.0.4".parse().unwrap();
        for i in 0..3u8 {
            assert_eq!(s.observe(&[i; 32], ip, 100).await, SybilDecision::Allow);
        }
        assert_eq!(
            s.observe(&[99u8; 32], ip, 100).await,
            SybilDecision::OverQuota
        );
        // After the window rolls over (10s), the set is cleared.
        assert_eq!(s.observe(&[99u8; 32], ip, 200).await, SybilDecision::Allow);
        let state = s.get(&ip).await.unwrap();
        assert_eq!(state.pubkeys.len(), 1);
    }

    #[tokio::test]
    async fn sybil_tracker_separate_ips_have_separate_quotas() {
        let s = IpSybilTracker::new(tight_sybil_policy());
        let ip1: IpAddr = "10.0.0.5".parse().unwrap();
        let ip2: IpAddr = "10.0.0.6".parse().unwrap();
        for i in 0..3u8 {
            assert_eq!(s.observe(&[i; 32], ip1, 100).await, SybilDecision::Allow);
        }
        // ip1 is now full. ip2 starts fresh.
        for i in 100..103u8 {
            assert_eq!(s.observe(&[i; 32], ip2, 100).await, SybilDecision::Allow);
        }
    }
}
