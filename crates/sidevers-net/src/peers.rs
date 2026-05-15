//! Peer table — local view of the network (spec §6.2, §6.4).
//!
//! Each node maintains a bounded set of known peers, populated through
//! peer-exchange (`PeerAsk`/`PeerTell`) and through observed connections.
//! The view drifts; it's not globally consistent. That's fine — the
//! protocol only needs paths to exist, not for everyone to agree on them.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use sidevers_core::messages::peer::PeerInfo;
use tokio::sync::RwLock;

/// Default upper bound on peer-table size.
pub const DEFAULT_MAX_PEERS: usize = 256;

/// In-memory peer directory. Inserts overwrite (and bump `last_seen`);
/// eviction is by oldest `last_seen` when the table is full.
#[derive(Clone)]
pub struct PeerTable {
    inner: Arc<RwLock<HashMap<[u8; 32], PeerInfo>>>,
    max: usize,
}

impl PeerTable {
    pub fn new(max: usize) -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            max,
        }
    }

    /// Insert or update a peer. If the table is at capacity and this is a new
    /// entry, evicts the oldest `last_seen`.
    pub async fn insert(&self, info: PeerInfo) {
        let mut guard = self.inner.write().await;
        if !guard.contains_key(&info.address) && guard.len() >= self.max {
            if let Some(oldest) = guard
                .iter()
                .min_by_key(|(_, p)| p.last_seen)
                .map(|(k, _)| *k)
            {
                guard.remove(&oldest);
            }
        }
        guard.insert(info.address, info);
    }

    /// Mark a peer as seen now (preserves other fields). No-op if not present.
    pub async fn touch(&self, address: &[u8; 32]) {
        if let Some(p) = self.inner.write().await.get_mut(address) {
            p.last_seen = unix_now();
        }
    }

    pub async fn get(&self, address: &[u8; 32]) -> Option<PeerInfo> {
        self.inner.read().await.get(address).cloned()
    }

    pub async fn remove(&self, address: &[u8; 32]) {
        self.inner.write().await.remove(address);
    }

    pub async fn len(&self) -> usize {
        self.inner.read().await.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }

    /// Snapshot a sample of peers, optionally filtered by an accepted intent.
    /// The result is sorted by `last_seen` descending so callers see the
    /// freshest peers first.
    pub async fn sample(&self, limit: usize, intent_filter: Option<u8>) -> Vec<PeerInfo> {
        let guard = self.inner.read().await;
        let mut all: Vec<PeerInfo> = guard
            .values()
            .filter(|p| match intent_filter {
                Some(want) => p.intents.contains(&want),
                None => true,
            })
            .cloned()
            .collect();
        all.sort_by_key(|p| std::cmp::Reverse(p.last_seen));
        all.truncate(limit);
        all
    }
}

impl Default for PeerTable {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_PEERS)
    }
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(addr: u8, last_seen: u64) -> PeerInfo {
        PeerInfo {
            address: [addr; 32],
            intents: vec![1, 3],
            endpoints: vec!["127.0.0.1:0".into()],
            last_seen,
        }
    }

    #[tokio::test]
    async fn insert_and_lookup() {
        let t = PeerTable::new(8);
        t.insert(info(1, 100)).await;
        let got = t.get(&[1u8; 32]).await.unwrap();
        assert_eq!(got.last_seen, 100);
        assert_eq!(t.len().await, 1);
    }

    #[tokio::test]
    async fn eviction_when_full() {
        let t = PeerTable::new(2);
        t.insert(info(1, 100)).await;
        t.insert(info(2, 200)).await;
        t.insert(info(3, 300)).await;
        assert_eq!(t.len().await, 2);
        // Oldest (last_seen=100) evicted.
        assert!(t.get(&[1u8; 32]).await.is_none());
        assert!(t.get(&[2u8; 32]).await.is_some());
        assert!(t.get(&[3u8; 32]).await.is_some());
    }

    #[tokio::test]
    async fn sample_respects_intent_filter() {
        let t = PeerTable::new(8);
        let mut a = info(1, 100);
        a.intents = vec![1];
        let mut b = info(2, 200);
        b.intents = vec![2];
        t.insert(a).await;
        t.insert(b).await;
        let s = t.sample(10, Some(2)).await;
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].address, [2u8; 32]);
    }

    #[tokio::test]
    async fn sample_orders_by_last_seen_desc() {
        let t = PeerTable::new(8);
        t.insert(info(1, 100)).await;
        t.insert(info(2, 300)).await;
        t.insert(info(3, 200)).await;
        let s = t.sample(10, None).await;
        let order: Vec<u64> = s.iter().map(|p| p.last_seen).collect();
        assert_eq!(order, vec![300, 200, 100]);
    }
}
