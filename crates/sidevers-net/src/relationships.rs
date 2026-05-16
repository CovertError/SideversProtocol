//! Per-side relationships and lifecycle state (protocol spec §7.4 + §7.8).
//!
//! Both are **local-only** state — never on the wire. Spec §7.4 is explicit:
//! "The protocol never publishes a side's contact list. Another node can't
//! ask 'who does this side know?' and get an answer." They live here next
//! to `PeerTable` (`peers.rs`) and `Mailbox` (`forward.rs`) — the other
//! local-only state modules.
//!
//! Relationships carry per-contact capability grants that **override** the
//! side's published profile (§7.7) for that one contact. An empty
//! capability set on a relationship explicitly means "block this contact"
//! (not "fall through to the profile"). See `capability_allows` in
//! `node.rs` for the lookup priority.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use tokio::sync::RwLock;

/// A side this node has a relationship with. Stored locally only.
/// Wire-equivalent of spec §7.4's `SideRelationship` CDDL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SideRelationship {
    /// The contact's side public key (Ed25519, 32 bytes).
    pub address: [u8; 32],
    /// Local display name. Side-scoped; never leaves the device.
    pub nickname: Option<String>,
    /// Optional pubkey of whoever introduced this contact (e.g. via
    /// `FriendIntroduction`-style flow). Not protocol-validated.
    pub introduced_by: Option<[u8; 32]>,
    /// Capability tokens this node accepts **from this specific contact**
    /// (§7.4). Empty set means "block." See spec §7.7 for the canonical
    /// token list (`direct-message`, `storage-host`, etc.).
    pub capabilities: BTreeSet<String>,
    /// Private notes about this contact.
    pub notes: Option<String>,
    /// Whether the contact is pinned to the top of the local list.
    pub pinned: bool,
    /// Unix seconds at which the relationship was first recorded.
    pub added_at: u64,
}

/// In-memory directory of relationships for this node's hosted side.
/// `insert` overwrites by address; `update` mutates in place under the
/// lock. Mirrors the API shape of `PeerTable` (`peers.rs`).
#[derive(Clone, Default)]
pub struct RelationshipTable {
    inner: Arc<RwLock<BTreeMap<[u8; 32], SideRelationship>>>,
}

impl RelationshipTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace a relationship.
    pub async fn insert(&self, r: SideRelationship) {
        self.inner.write().await.insert(r.address, r);
    }

    /// Return a clone of the relationship for `address`, if any.
    pub async fn get(&self, address: &[u8; 32]) -> Option<SideRelationship> {
        self.inner.read().await.get(address).cloned()
    }

    /// Remove a relationship. No-op if not present.
    pub async fn remove(&self, address: &[u8; 32]) {
        self.inner.write().await.remove(address);
    }

    /// True iff a relationship exists for `address`. Used by the
    /// capability lookup to distinguish "no relationship → fall through
    /// to profile" from "empty-set relationship → block."
    pub async fn contains(&self, address: &[u8; 32]) -> bool {
        self.inner.read().await.contains_key(address)
    }

    /// Snapshot all relationships, ordered by address (BTreeMap iteration).
    pub async fn list(&self) -> Vec<SideRelationship> {
        self.inner.read().await.values().cloned().collect()
    }

    pub async fn len(&self) -> usize {
        self.inner.read().await.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.inner.read().await.is_empty()
    }

    /// Mutate a relationship in place under the lock. Returns `true` if
    /// the entry existed (and was passed to `f`), `false` otherwise.
    pub async fn update<F>(&self, address: &[u8; 32], f: F) -> bool
    where
        F: FnOnce(&mut SideRelationship),
    {
        let mut guard = self.inner.write().await;
        match guard.get_mut(address) {
            Some(r) => {
                f(r);
                true
            }
            None => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Side lifecycle (§7.8)
// ---------------------------------------------------------------------------

/// The four life stages a side moves through, per spec §7.8.
/// Created/Active/Dormant are local UI affordances derived from activity;
/// only Retired has an on-the-wire signal (`SideRetirementPayload`,
/// implemented in Phase 1.5d).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SideLifecycle {
    /// Just minted; no envelopes sent yet.
    Created,
    /// Last local send was within `DORMANT_AFTER_SECS`.
    Active,
    /// Last local send was longer ago than `DORMANT_AFTER_SECS`, but the
    /// side has not been retired.
    Dormant,
    /// A signed retirement record has been published for this side.
    Retired,
}

/// Default activity window for the Active → Dormant transition (90 days).
/// Spec §7.8 doesn't pin a specific window; this is a reasonable default.
/// Exposed as `pub const` so callers can read it (e.g. UI badges).
pub const DORMANT_AFTER_SECS: u64 = 90 * 24 * 3600;

impl SideLifecycle {
    /// Pure derivation: given the last local-send timestamp (or `None`),
    /// the "have I retired?" flag, and `now` in unix seconds, return the
    /// corresponding lifecycle state. Retirement dominates; otherwise the
    /// activity window picks between Created/Active/Dormant.
    pub fn derive(last_send_at: Option<u64>, retired: bool, now: u64) -> Self {
        if retired {
            return SideLifecycle::Retired;
        }
        match last_send_at {
            None => SideLifecycle::Created,
            Some(ts) if now.saturating_sub(ts) < DORMANT_AFTER_SECS => SideLifecycle::Active,
            Some(_) => SideLifecycle::Dormant,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rel(addr: u8, caps: &[&str]) -> SideRelationship {
        let mut set = BTreeSet::new();
        for c in caps {
            set.insert((*c).to_owned());
        }
        SideRelationship {
            address: [addr; 32],
            nickname: None,
            introduced_by: None,
            capabilities: set,
            notes: None,
            pinned: false,
            added_at: 1_700_000_000,
        }
    }

    #[tokio::test]
    async fn insert_get_remove_round_trip() {
        let t = RelationshipTable::new();
        t.insert(rel(1, &["direct-message"])).await;
        assert!(t.contains(&[1u8; 32]).await);
        let got = t.get(&[1u8; 32]).await.unwrap();
        assert!(got.capabilities.contains("direct-message"));
        t.remove(&[1u8; 32]).await;
        assert!(t.get(&[1u8; 32]).await.is_none());
        assert!(t.is_empty().await);
    }

    #[tokio::test]
    async fn update_mutates_in_place() {
        let t = RelationshipTable::new();
        t.insert(rel(1, &["direct-message"])).await;
        let changed = t
            .update(&[1u8; 32], |r| {
                r.nickname = Some("alice".into());
                r.pinned = true;
            })
            .await;
        assert!(changed);
        let got = t.get(&[1u8; 32]).await.unwrap();
        assert_eq!(got.nickname.as_deref(), Some("alice"));
        assert!(got.pinned);
    }

    #[tokio::test]
    async fn update_returns_false_when_absent() {
        let t = RelationshipTable::new();
        let changed = t.update(&[9u8; 32], |r| r.pinned = true).await;
        assert!(!changed);
    }

    #[tokio::test]
    async fn list_returns_all_entries() {
        let t = RelationshipTable::new();
        t.insert(rel(1, &[])).await;
        t.insert(rel(2, &["direct-message"])).await;
        t.insert(rel(3, &[])).await;
        let all = t.list().await;
        assert_eq!(all.len(), 3);
    }

    #[tokio::test]
    async fn empty_capability_set_round_trips() {
        // Empty-set relationship = "block this contact" semantics.
        let t = RelationshipTable::new();
        t.insert(rel(1, &[])).await;
        let got = t.get(&[1u8; 32]).await.unwrap();
        assert!(got.capabilities.is_empty());
        // contains() is still true — the relationship exists.
        assert!(t.contains(&[1u8; 32]).await);
    }

    #[test]
    fn lifecycle_derive_pure() {
        // Use a realistic 2026-era timestamp so `now - DORMANT_AFTER_SECS`
        // doesn't underflow.
        let now: u64 = 1_700_000_000;
        // No sends yet → Created.
        assert_eq!(
            SideLifecycle::derive(None, false, now),
            SideLifecycle::Created
        );
        // Recent send → Active.
        assert_eq!(
            SideLifecycle::derive(Some(now - 60), false, now),
            SideLifecycle::Active
        );
        // Just inside the window → still Active.
        assert_eq!(
            SideLifecycle::derive(Some(now - DORMANT_AFTER_SECS + 1), false, now),
            SideLifecycle::Active
        );
        // Just outside the window → Dormant.
        assert_eq!(
            SideLifecycle::derive(Some(now - DORMANT_AFTER_SECS), false, now),
            SideLifecycle::Dormant
        );
        // Long-ago send → Dormant.
        assert_eq!(
            SideLifecycle::derive(Some(now - 10 * DORMANT_AFTER_SECS), false, now),
            SideLifecycle::Dormant
        );
        // Retirement dominates regardless of last_send_at.
        assert_eq!(
            SideLifecycle::derive(None, true, now),
            SideLifecycle::Retired
        );
        assert_eq!(
            SideLifecycle::derive(Some(now), true, now),
            SideLifecycle::Retired
        );
    }
}
