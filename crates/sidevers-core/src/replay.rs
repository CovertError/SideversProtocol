//! Replay-attack guard for envelope nonces (protocol spec §3.2).
//!
//! Recipients SHOULD cache `(from, nonce)` pairs for at least 600 seconds
//! to detect replays. The cache eviction policy is sweep-based, not
//! touched-on-hit: an attacker MUST NOT be able to keep a replay alive by
//! repeatedly submitting it within the TTL.
//!
//! This module is a single-process in-memory cache. Multi-process / cluster
//! deployments would back it with a shared store; that's outside the current
//! Phase-1 scope.

use std::collections::HashMap;

use crate::envelope::NONCE_LEN;
use crate::keys::PUBLIC_KEY_LEN;

/// Default replay-cache TTL (§3.2 SHOULD: "at least 600 seconds").
pub const DEFAULT_TTL_SECS: u64 = 600;

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
struct Key {
    from: [u8; PUBLIC_KEY_LEN],
    nonce: [u8; NONCE_LEN],
}

/// In-memory replay-detection cache. Stores `(from, nonce) -> first_seen_ts`.
///
/// `now_ts_secs` is supplied by callers so this struct is unit-testable
/// without time-of-day mocking.
pub struct ReplayCache {
    ttl: u64,
    entries: HashMap<Key, u64>,
}

impl ReplayCache {
    pub fn new() -> Self {
        Self::with_ttl(DEFAULT_TTL_SECS)
    }

    pub fn with_ttl(ttl_secs: u64) -> Self {
        Self {
            ttl: ttl_secs,
            entries: HashMap::new(),
        }
    }

    /// Record this `(from, nonce)` at the given timestamp. Returns `true` if
    /// the pair was already in the cache (i.e. this is a replay). Either way
    /// the cache's existing `first_seen` is preserved — we do NOT touch the
    /// TTL on a hit. That keeps an attacker from keeping a replay alive.
    pub fn observe(
        &mut self,
        now_ts_secs: u64,
        from: &[u8; PUBLIC_KEY_LEN],
        nonce: &[u8; NONCE_LEN],
    ) -> bool {
        use std::collections::hash_map::Entry;
        self.sweep(now_ts_secs);
        let key = Key {
            from: *from,
            nonce: *nonce,
        };
        match self.entries.entry(key) {
            Entry::Vacant(e) => {
                e.insert(now_ts_secs);
                false
            }
            Entry::Occupied(_) => true,
        }
    }

    /// Remove expired entries.
    pub fn sweep(&mut self, now_ts_secs: u64) {
        let ttl = self.ttl;
        self.entries
            .retain(|_, first_seen| now_ts_secs.saturating_sub(*first_seen) < ttl);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for ReplayCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_pair() -> ([u8; PUBLIC_KEY_LEN], [u8; NONCE_LEN]) {
        ([7u8; PUBLIC_KEY_LEN], [3u8; NONCE_LEN])
    }

    #[test]
    fn first_observation_is_not_replay() {
        let mut c = ReplayCache::with_ttl(600);
        let (from, nonce) = key_pair();
        assert!(!c.observe(1000, &from, &nonce));
    }

    #[test]
    fn second_observation_within_ttl_is_replay() {
        let mut c = ReplayCache::with_ttl(600);
        let (from, nonce) = key_pair();
        assert!(!c.observe(1000, &from, &nonce));
        assert!(c.observe(1100, &from, &nonce));
        assert!(c.observe(1500, &from, &nonce));
    }

    #[test]
    fn ttl_expiry_allows_reuse() {
        let mut c = ReplayCache::with_ttl(600);
        let (from, nonce) = key_pair();
        assert!(!c.observe(1000, &from, &nonce));
        assert!(!c.observe(2000, &from, &nonce), "after TTL, not a replay");
    }

    #[test]
    fn ttl_does_not_refresh_on_hit() {
        // The key insight: an attacker cannot extend the cache lifetime of an
        // entry by repeatedly replaying it. If they hammer it, eviction still
        // happens at first_seen + ttl, not last_seen + ttl.
        let mut c = ReplayCache::with_ttl(600);
        let (from, nonce) = key_pair();
        assert!(!c.observe(1000, &from, &nonce));
        // Hammer the cache.
        for t in 1100..1600 {
            assert!(c.observe(t, &from, &nonce));
        }
        // After original TTL passes, the entry is gone — attacker did not
        // succeed in keeping it alive.
        c.sweep(1601);
        assert_eq!(c.len(), 0);
    }

    #[test]
    fn different_from_or_nonce_is_not_replay() {
        let mut c = ReplayCache::with_ttl(600);
        let (from1, nonce1) = ([1u8; PUBLIC_KEY_LEN], [1u8; NONCE_LEN]);
        let from2 = [2u8; PUBLIC_KEY_LEN];
        let nonce2 = [2u8; NONCE_LEN];
        assert!(!c.observe(1000, &from1, &nonce1));
        assert!(!c.observe(1000, &from2, &nonce1));
        assert!(!c.observe(1000, &from1, &nonce2));
    }
}
