//! Phase 1.C3: per-object publisher provenance for storage retract.
//!
//! When a node ingests a content-addressed object via STORAGE_OFFER, it
//! records the envelope sender as a "publisher" of that hash. A
//! subsequent STORAGE_RETRACT is only honored if the retracter is one
//! of the recorded publishers — otherwise an adversary could cause us
//! to drop someone else's data simply by sending us a signed retract.
//!
//! Removal semantics: a retract removes the retracter from the
//! object's publisher set. Only when the set becomes empty do we
//! actually unpin the object — otherwise other publishers might still
//! be referencing it. This narrows retract from "any peer drops the
//! object" (overbroad) to "the last publisher to retract causes the
//! drop" (proper provenance).
//!
//! Memory model: this is an in-memory table. Restart loses the
//! provenance, which is acceptable for Phase 1 — retract is documented
//! as best-effort (§5.6) and the worst case after a restart is "we
//! over-trust a single retract for objects we ingested before the
//! restart." Future hardening could persist alongside `replay_journal`.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use sidevers_core::keys::PUBLIC_KEY_LEN;
use tokio::sync::Mutex;

type Hash = [u8; 32];
type Side = [u8; PUBLIC_KEY_LEN];

#[derive(Debug, Clone, Default)]
pub struct PublisherTable {
    inner: Arc<Mutex<HashMap<Hash, BTreeSet<Side>>>>,
}

impl PublisherTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `side` as a publisher of the object with `hash`. Idempotent.
    pub async fn note_publisher(&self, hash: &Hash, side: &Side) {
        let mut tab = self.inner.lock().await;
        tab.entry(*hash).or_default().insert(*side);
    }

    /// True iff `side` is currently recorded as a publisher of `hash`.
    pub async fn has_publisher(&self, hash: &Hash, side: &Side) -> bool {
        let tab = self.inner.lock().await;
        tab.get(hash).is_some_and(|s| s.contains(side))
    }

    /// Forget `side` as a publisher of `hash`. Returns `true` iff at
    /// least one OTHER publisher is still recorded after the removal
    /// (i.e., the object is still backed by some publisher and the
    /// caller should NOT unpin). Returns `false` if the set became
    /// empty or didn't contain `side` to begin with.
    pub async fn drop_publisher(&self, hash: &Hash, side: &Side) -> bool {
        let mut tab = self.inner.lock().await;
        let Some(set) = tab.get_mut(hash) else {
            return false;
        };
        set.remove(side);
        if set.is_empty() {
            tab.remove(hash);
            false
        } else {
            true
        }
    }

    /// Snapshot the current publisher set for `hash`, for tests / diagnostics.
    pub async fn publishers(&self, hash: &Hash) -> BTreeSet<Side> {
        let tab = self.inner.lock().await;
        tab.get(hash).cloned().unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn note_then_check_publisher() {
        let t = PublisherTable::new();
        let h = [0x11; 32];
        let a = [0xAA; PUBLIC_KEY_LEN];
        let b = [0xBB; PUBLIC_KEY_LEN];
        t.note_publisher(&h, &a).await;
        assert!(t.has_publisher(&h, &a).await);
        assert!(!t.has_publisher(&h, &b).await);
    }

    #[tokio::test]
    async fn drop_publisher_returns_true_when_others_remain() {
        let t = PublisherTable::new();
        let h = [0x11; 32];
        let a = [0xAA; PUBLIC_KEY_LEN];
        let b = [0xBB; PUBLIC_KEY_LEN];
        t.note_publisher(&h, &a).await;
        t.note_publisher(&h, &b).await;
        assert!(t.drop_publisher(&h, &a).await, "b still publishes");
        assert!(!t.drop_publisher(&h, &b).await, "now empty");
    }

    #[tokio::test]
    async fn drop_unknown_publisher_is_noop() {
        let t = PublisherTable::new();
        let h = [0x11; 32];
        let a = [0xAA; PUBLIC_KEY_LEN];
        // Object was never published — nothing to drop.
        assert!(!t.drop_publisher(&h, &a).await);
    }
}
