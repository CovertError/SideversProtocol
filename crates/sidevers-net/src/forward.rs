//! Store-and-forward mailbox (spec §6.7).
//!
//! When a recipient is offline, any node can hold a sealed envelope for
//! them and deliver it later. The forwarder sees only the outer envelope
//! header (so it knows the `to` field for routing); the inner envelope is
//! end-to-end encrypted to the recipient, so the forwarder cannot read it.
//!
//! Month-4 implementation:
//!   * In-memory FIFO per recipient.
//!   * TTL eviction (default 7 days, per spec §6.7).
//!   * No persistence — restarting a forwarder loses its mailbox.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::Mutex;

use crate::peers::unix_now;

/// Spec §6.7 default TTL for store-and-forward (7 days).
pub const DEFAULT_TTL_SECS: u64 = 7 * 24 * 60 * 60;

/// One held message, ready to be sent when the recipient appears.
#[derive(Debug, Clone)]
pub struct HeldMessage {
    /// The inner envelope bytes (already signed + sealed by the original sender).
    pub envelope: Vec<u8>,
    pub stored_at: u64,
    pub expires_at: u64,
}

#[derive(Clone, Default)]
pub struct Mailbox {
    inner: Arc<Mutex<HashMap<[u8; 32], Vec<HeldMessage>>>>,
}

impl Mailbox {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add one envelope for `recipient`. Honors `ttl_secs` from caller; if it
    /// exceeds the default cap, clamp to default.
    pub async fn store(&self, recipient: [u8; 32], envelope: Vec<u8>, ttl_secs: u64) {
        let now = unix_now();
        let ttl = ttl_secs.min(DEFAULT_TTL_SECS);
        let held = HeldMessage {
            envelope,
            stored_at: now,
            expires_at: now + ttl,
        };
        let mut guard = self.inner.lock().await;
        guard.entry(recipient).or_default().push(held);
    }

    /// Pop and return everything we're holding for `recipient`, dropping
    /// anything past its TTL.
    pub async fn drain(&self, recipient: &[u8; 32]) -> Vec<HeldMessage> {
        let now = unix_now();
        let mut guard = self.inner.lock().await;
        let queue = guard.remove(recipient).unwrap_or_default();
        queue.into_iter().filter(|m| m.expires_at > now).collect()
    }

    /// Read the count without consuming. Mostly useful for tests.
    pub async fn len_for(&self, recipient: &[u8; 32]) -> usize {
        self.inner
            .lock()
            .await
            .get(recipient)
            .map(|q| q.len())
            .unwrap_or(0)
    }

    /// Sweep all expired entries across all recipients.
    pub async fn sweep(&self) -> usize {
        let now = unix_now();
        let mut guard = self.inner.lock().await;
        let mut dropped = 0usize;
        guard.retain(|_, queue| {
            let before = queue.len();
            queue.retain(|m| m.expires_at > now);
            dropped += before - queue.len();
            !queue.is_empty()
        });
        dropped
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn store_then_drain_returns_in_order() {
        let m = Mailbox::new();
        let r = [1u8; 32];
        m.store(r, vec![0x01], 60).await;
        m.store(r, vec![0x02], 60).await;
        let drained = m.drain(&r).await;
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].envelope, vec![0x01]);
        assert_eq!(drained[1].envelope, vec![0x02]);
        // Drain emptied the mailbox.
        assert_eq!(m.len_for(&r).await, 0);
    }

    #[tokio::test]
    async fn drain_unknown_recipient_is_empty() {
        let m = Mailbox::new();
        let drained = m.drain(&[9u8; 32]).await;
        assert!(drained.is_empty());
    }
}
