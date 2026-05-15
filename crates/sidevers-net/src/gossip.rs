//! Gossip propagation for public content (spec §6.8).
//!
//! A node maintains:
//!   * **subscriptions** — publisher addresses this node cares about
//!   * **dedup cache**  — (from, nonce) of recently-seen broadcasts
//!
//! When a public (broadcast) envelope arrives:
//!   1. Drop it if (from, nonce) is in the cache (already seen).
//!   2. Insert into dedup cache.
//!   3. If the publisher is in our subscriptions, forward to interested peers.
//!
//! Spec §6.9 calls for web-of-trust filtering. For Month 4 we use the simpler
//! subscription set as the filter; web-of-trust over the follow graph is a
//! Phase-2 refinement once profiles exist.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use sidevers_core::Envelope;
use tokio::sync::RwLock;

use crate::peers::unix_now;

/// How long to remember `(from, nonce)` pairs for dedup. Per spec §3.2 the
/// replay window is at least 600 s; we use the same here.
pub const DEDUP_TTL_SECS: u64 = 600;

/// Maximum dedup entries before we sweep aggressively.
const MAX_DEDUP_ENTRIES: usize = 10_000;

#[derive(Clone, Default)]
pub struct GossipState {
    subs: Arc<RwLock<HashSet<[u8; 32]>>>,
    dedup: Arc<RwLock<HashMap<DedupKey, u64>>>,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct DedupKey {
    from: [u8; 32],
    nonce: [u8; 16],
}

impl GossipState {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn subscribe(&self, publisher: [u8; 32]) {
        self.subs.write().await.insert(publisher);
    }

    pub async fn unsubscribe(&self, publisher: &[u8; 32]) {
        self.subs.write().await.remove(publisher);
    }

    pub async fn subscriptions(&self) -> Vec<[u8; 32]> {
        self.subs.read().await.iter().copied().collect()
    }

    /// Returns `true` if this is the first time we've seen this envelope.
    /// On `true`, the envelope is recorded for future dedup.
    pub async fn observe(&self, env: &Envelope) -> bool {
        let mut guard = self.dedup.write().await;
        let key = DedupKey {
            from: env.from,
            nonce: env.nonce,
        };
        let now = unix_now();
        // Sweep cheaply when the cache gets large.
        if guard.len() >= MAX_DEDUP_ENTRIES {
            guard.retain(|_, ts| now.saturating_sub(*ts) < DEDUP_TTL_SECS);
        }
        match guard.entry(key) {
            std::collections::hash_map::Entry::Vacant(e) => {
                e.insert(now);
                true
            }
            std::collections::hash_map::Entry::Occupied(_) => false,
        }
    }

    /// Does this node want to act on broadcasts from `publisher`? Currently
    /// "yes iff we subscribed."
    pub async fn is_interesting(&self, publisher: &[u8; 32]) -> bool {
        self.subs.read().await.contains(publisher)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sidevers_core::MessageType;
    use sidevers_core::envelope::NONCE_LEN;
    use sidevers_core::keys::MasterKey;

    fn make_broadcast_envelope(seed: u8, nonce: [u8; NONCE_LEN]) -> Envelope {
        let master = MasterKey::from_seed(&[seed; 32]);
        let side = master.derive_side(&"public".into()).unwrap();
        Envelope::sign_with(
            MessageType(0x65), // Announcement-like (Public range)
            &side,
            None,
            b"public news".to_vec(),
            1_700_000_000,
            nonce,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn first_observation_is_fresh() {
        let g = GossipState::new();
        let env = make_broadcast_envelope(1, [9u8; NONCE_LEN]);
        assert!(g.observe(&env).await);
        assert!(!g.observe(&env).await);
    }

    #[tokio::test]
    async fn different_nonces_are_independent() {
        let g = GossipState::new();
        let e1 = make_broadcast_envelope(1, [1u8; NONCE_LEN]);
        let e2 = make_broadcast_envelope(1, [2u8; NONCE_LEN]);
        assert!(g.observe(&e1).await);
        assert!(g.observe(&e2).await);
    }

    #[tokio::test]
    async fn subscribe_then_check_interest() {
        let g = GossipState::new();
        let pub_addr = [7u8; 32];
        assert!(!g.is_interesting(&pub_addr).await);
        g.subscribe(pub_addr).await;
        assert!(g.is_interesting(&pub_addr).await);
        g.unsubscribe(&pub_addr).await;
        assert!(!g.is_interesting(&pub_addr).await);
    }
}
