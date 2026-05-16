//! Replay-attack guard for envelope nonces (protocol spec §3.2).
//!
//! Recipients SHOULD cache `(from, nonce)` pairs for at least 600 seconds
//! to detect replays. The cache eviction policy is sweep-based, not
//! touched-on-hit: an attacker MUST NOT be able to keep a replay alive by
//! repeatedly submitting it within the TTL.
//!
//! ## Memory bound (Phase 1.E)
//!
//! The cache enforces a hard `max_entries` cap so an attacker cannot fill
//! arbitrary memory by pumping fresh `(from, nonce)` pairs. When the cache
//! is at capacity, the oldest entry by `first_seen` is evicted to make
//! room. Eviction is O(N) at the moment (linear scan) but bounded by
//! `max_entries`, so the DoS surface is `O(max_entries)` per insertion at
//! worst.
//!
//! ## Persistence (Phase 1.E)
//!
//! Optional write-through journal lets the cache survive a process
//! restart: register a `ReplayJournal` and the cache records inserts +
//! evictions to durable storage. On startup, callers preload journaled
//! entries with `preload`. The trait is sync because every cache mutation
//! is already under a single mutex.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use crate::envelope::NONCE_LEN;
use crate::keys::PUBLIC_KEY_LEN;

/// Default replay-cache TTL (§3.2 SHOULD: "at least 600 seconds").
pub const DEFAULT_TTL_SECS: u64 = 600;

/// Default cap on the number of `(from, nonce)` entries the cache will
/// hold simultaneously. Sized for a realistic per-side traffic rate: at
/// the default refill of 10 envelopes/s with TTL 600 s, ~6 000 entries is
/// the steady-state worst case; 16 384 leaves headroom and bounds memory
/// at <1 MiB per cache.
pub const DEFAULT_MAX_ENTRIES: usize = 16_384;

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
struct Key {
    from: [u8; PUBLIC_KEY_LEN],
    nonce: [u8; NONCE_LEN],
}

/// Hook for persisting cache mutations. Implementations are typically
/// thin SQLite-or-other-K/V wrappers. Methods are sync and infallible:
/// the cache calls them while holding its lock, and any IO failure must
/// be handled internally (e.g. swallow + log + retry) rather than
/// propagated up — losing a journal write degrades replay protection
/// across a restart but never breaks in-memory operation.
pub trait ReplayJournal: Send + Sync + fmt::Debug {
    fn record(&self, from: &[u8; PUBLIC_KEY_LEN], nonce: &[u8; NONCE_LEN], first_seen: u64);
    fn evict(&self, from: &[u8; PUBLIC_KEY_LEN], nonce: &[u8; NONCE_LEN]);
}

/// In-memory replay-detection cache with optional write-through
/// persistence. Stores `(from, nonce) -> first_seen_ts`.
///
/// `now_ts_secs` is supplied by callers so this struct is unit-testable
/// without time-of-day mocking.
pub struct ReplayCache {
    ttl: u64,
    max_entries: usize,
    entries: HashMap<Key, u64>,
    journal: Option<Arc<dyn ReplayJournal>>,
}

impl ReplayCache {
    pub fn new() -> Self {
        Self::with_ttl(DEFAULT_TTL_SECS)
    }

    pub fn with_ttl(ttl_secs: u64) -> Self {
        Self::with_capacity(ttl_secs, DEFAULT_MAX_ENTRIES)
    }

    pub fn with_capacity(ttl_secs: u64, max_entries: usize) -> Self {
        Self {
            ttl: ttl_secs,
            max_entries: max_entries.max(1),
            entries: HashMap::new(),
            journal: None,
        }
    }

    /// Attach a journal. Subsequent `observe` / `sweep` calls record
    /// inserts + evictions through it. Existing entries are NOT replayed
    /// into the journal — call `preload` first if the cache contains
    /// state that should be journaled retroactively.
    pub fn set_journal(&mut self, journal: Arc<dyn ReplayJournal>) {
        self.journal = Some(journal);
    }

    /// Insert journaled entries from a prior run, skipping any whose age
    /// exceeds the TTL. Callers typically read these from the persistent
    /// journal at startup. Does NOT trigger journal callbacks (the
    /// entries are already on disk).
    pub fn preload(
        &mut self,
        now_ts_secs: u64,
        entries: impl IntoIterator<Item = ([u8; PUBLIC_KEY_LEN], [u8; NONCE_LEN], u64)>,
    ) {
        for (from, nonce, first_seen) in entries {
            if now_ts_secs.saturating_sub(first_seen) >= self.ttl {
                continue;
            }
            let key = Key { from, nonce };
            self.entries.insert(key, first_seen);
        }
        // If preload overshot the cap (e.g. spec change shrank
        // max_entries between runs), trim oldest now.
        while self.entries.len() > self.max_entries {
            if let Some(oldest) = self.find_oldest_key() {
                self.entries.remove(&oldest);
                // Don't journal-evict during preload — caller hasn't
                // attached a journal yet (preload runs before
                // set_journal in the wiring).
            } else {
                break;
            }
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
            Entry::Vacant(_) => {
                // Enforce the cap *before* insert so we never exceed it.
                if self.entries.len() >= self.max_entries
                    && let Some(oldest) = Self::find_oldest_in(&self.entries)
                {
                    self.entries.remove(&oldest);
                    if let Some(j) = &self.journal {
                        j.evict(&oldest.from, &oldest.nonce);
                    }
                }
                // Re-enter the entry API in case the borrow above invalidated it.
                self.entries.insert(key, now_ts_secs);
                if let Some(j) = &self.journal {
                    j.record(from, nonce, now_ts_secs);
                }
                false
            }
            Entry::Occupied(_) => true,
        }
    }

    /// Remove expired entries.
    pub fn sweep(&mut self, now_ts_secs: u64) {
        let ttl = self.ttl;
        let journal = self.journal.clone();
        self.entries.retain(|k, first_seen| {
            let alive = now_ts_secs.saturating_sub(*first_seen) < ttl;
            if !alive && let Some(j) = &journal {
                j.evict(&k.from, &k.nonce);
            }
            alive
        });
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn max_entries(&self) -> usize {
        self.max_entries
    }

    fn find_oldest_key(&self) -> Option<Key> {
        Self::find_oldest_in(&self.entries)
    }

    fn find_oldest_in(entries: &HashMap<Key, u64>) -> Option<Key> {
        entries
            .iter()
            .min_by_key(|(_, first_seen)| **first_seen)
            .map(|(k, _)| *k)
    }
}

impl Default for ReplayCache {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ReplayCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReplayCache")
            .field("ttl", &self.ttl)
            .field("max_entries", &self.max_entries)
            .field("entries", &self.entries.len())
            .field("journal_attached", &self.journal.is_some())
            .finish()
    }
}

// Box impl makes Box<dyn ReplayJournal> work as Arc<dyn ReplayJournal>
// via Into; not strictly needed but useful for ergonomic callers.
impl<T: ReplayJournal + ?Sized> ReplayJournal for Box<T> {
    fn record(&self, from: &[u8; PUBLIC_KEY_LEN], nonce: &[u8; NONCE_LEN], first_seen: u64) {
        (**self).record(from, nonce, first_seen);
    }
    fn evict(&self, from: &[u8; PUBLIC_KEY_LEN], nonce: &[u8; NONCE_LEN]) {
        (**self).evict(from, nonce);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

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
        let mut c = ReplayCache::with_ttl(600);
        let (from, nonce) = key_pair();
        assert!(!c.observe(1000, &from, &nonce));
        for t in 1100..1600 {
            assert!(c.observe(t, &from, &nonce));
        }
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

    // ---- Phase 1.E: memory bound + journal ----

    #[test]
    fn cap_evicts_oldest_when_full() {
        let mut c = ReplayCache::with_capacity(600, 3);
        let nonce = |i: u8| [i; NONCE_LEN];
        let from = [9u8; PUBLIC_KEY_LEN];
        c.observe(1000, &from, &nonce(1));
        c.observe(1100, &from, &nonce(2));
        c.observe(1200, &from, &nonce(3));
        assert_eq!(c.len(), 3);
        // Insert a fourth at t=1300; the oldest (nonce(1)) gets evicted.
        c.observe(1300, &from, &nonce(4));
        assert_eq!(c.len(), 3);
        // nonce(1) should NOT be a replay anymore — it was evicted.
        assert!(!c.observe(1400, &from, &nonce(1)));
        // But that insert itself pushed us over, so something else was evicted.
        assert_eq!(c.len(), 3);
    }

    type RecordedInsert = ([u8; PUBLIC_KEY_LEN], [u8; NONCE_LEN], u64);
    type RecordedEvict = ([u8; PUBLIC_KEY_LEN], [u8; NONCE_LEN]);

    #[derive(Debug, Default)]
    struct RecordingJournal {
        records: Mutex<Vec<RecordedInsert>>,
        evictions: Mutex<Vec<RecordedEvict>>,
    }
    impl ReplayJournal for RecordingJournal {
        fn record(&self, from: &[u8; PUBLIC_KEY_LEN], nonce: &[u8; NONCE_LEN], first_seen: u64) {
            self.records
                .lock()
                .unwrap()
                .push((*from, *nonce, first_seen));
        }
        fn evict(&self, from: &[u8; PUBLIC_KEY_LEN], nonce: &[u8; NONCE_LEN]) {
            self.evictions.lock().unwrap().push((*from, *nonce));
        }
    }

    #[test]
    fn journal_sees_inserts_and_sweeps() {
        let journal = Arc::new(RecordingJournal::default());
        let mut c = ReplayCache::with_ttl(600);
        c.set_journal(journal.clone());
        let (from, nonce) = key_pair();
        c.observe(1000, &from, &nonce);
        // Force expiry.
        c.sweep(2000);
        assert_eq!(journal.records.lock().unwrap().len(), 1);
        assert_eq!(journal.evictions.lock().unwrap().len(), 1);
    }

    #[test]
    fn preload_skips_already_expired_entries() {
        let mut c = ReplayCache::with_ttl(600);
        let (from, nonce) = key_pair();
        // Entry at t=1000; current time t=2000 → already older than TTL.
        c.preload(2000, [(from, nonce, 1000)]);
        // Cache should be empty since the preloaded entry was stale.
        assert!(c.is_empty());
        // And a fresh observation is therefore not a replay.
        assert!(!c.observe(2000, &from, &nonce));
    }

    #[test]
    fn preload_keeps_fresh_entries_and_blocks_replay() {
        let mut c = ReplayCache::with_ttl(600);
        let (from, nonce) = key_pair();
        c.preload(1100, [(from, nonce, 1000)]);
        // Same (from, nonce) observed again within TTL → flagged as replay.
        assert!(c.observe(1150, &from, &nonce));
    }
}
