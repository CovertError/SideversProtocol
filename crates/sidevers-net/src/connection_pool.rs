//! Phase 1.H4: QUIC connection pool keyed on `(peer_addr, source_side)`.
//!
//! `Node::dial` opens a fresh `quinn::Connection` (full TLS + QUIC
//! handshake — kilobytes of crypto, RTT to remote, fresh nonces) every
//! time. For ping-pong patterns (DMs, repeated storage lookups) that
//! cost dominates. This module caches the underlying QUIC connection
//! per `(peer_addr, source_side)` so subsequent dials reuse the open
//! connection and pay only for the inner Sidevers handshake (3 small
//! envelopes on a fresh bi-stream).
//!
//! The protocol handshake (Hello / HelloBack / Confirm) is still run
//! for each new `Session` — that's where intent + session-key
//! freshness lives. We only pool the transport.
//!
//! Eviction: lazy. On each lookup we discard cached connections whose
//! `close_reason()` is `Some(..)` (peer closed, transport gave up,
//! etc.).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::Mutex;

/// Map key: (peer_addr, source_side_pubkey). The source side matters
/// because per spec §7.6 each hosted side has its own QUIC endpoint;
/// two sides on the same node MUST NOT multiplex over one connection.
type Key = (SocketAddr, [u8; 32]);

#[derive(Debug, Clone, Default)]
pub struct ConnectionPool {
    inner: Arc<Mutex<HashMap<Key, quinn::Connection>>>,
}

impl ConnectionPool {
    pub fn new() -> Self {
        Self::default()
    }

    /// Return a cached connection to `peer_addr` from `source_side` if
    /// one exists and is still alive, otherwise `None`. Drops the
    /// entry from the cache as a side effect if it's been closed.
    pub async fn get(
        &self,
        peer_addr: SocketAddr,
        source_side: &[u8; 32],
    ) -> Option<quinn::Connection> {
        let key: Key = (peer_addr, *source_side);
        let mut tab = self.inner.lock().await;
        // Sweep dead entries while we hold the lock — cheap and keeps
        // the map bounded by the number of currently-live peers.
        tab.retain(|_, c| c.close_reason().is_none());
        tab.get(&key).cloned()
    }

    /// Insert (or replace) a connection in the cache.
    pub async fn insert(
        &self,
        peer_addr: SocketAddr,
        source_side: [u8; 32],
        conn: quinn::Connection,
    ) {
        let mut tab = self.inner.lock().await;
        tab.insert((peer_addr, source_side), conn);
    }

    /// Remove a connection (e.g. after a handshake fails and the
    /// caller knows it's dead).
    pub async fn invalidate(&self, peer_addr: SocketAddr, source_side: &[u8; 32]) {
        let mut tab = self.inner.lock().await;
        tab.remove(&(peer_addr, *source_side));
    }

    /// Total cached connections. Mostly useful for tests + metrics.
    pub async fn len(&self) -> usize {
        let mut tab = self.inner.lock().await;
        tab.retain(|_, c| c.close_reason().is_none());
        tab.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }

    /// Drop every cached connection (does not actively close them —
    /// QUIC connections close themselves once the last handle drops).
    pub async fn clear(&self) {
        self.inner.lock().await.clear();
    }
}
