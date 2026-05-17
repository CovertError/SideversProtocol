//! Hosting state for a single verse (Phase 1.5a + 1.5b).
//!
//! A `VerseHost` is the per-node state needed to act as a verse's home
//! node: the verse's own keypair (signing contracts, membership tokens, and
//! removal records), the current contract, the verse content key, the set
//! of admitted members, the contract-version each member has consented to,
//! and the live gossip-style mapping from member side public-key to their
//! active QUIC connection (for post fanout and key-rotation push).
//!
//! Phase 1.5a allows at most one hosted verse per Node; multiple hosted
//! verses is a Phase 1.5c extension.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use sidevers_core::Envelope;
use sidevers_core::keys::{PUBLIC_KEY_LEN, SideKey};
use sidevers_core::verse::{ContractObject, VerseContentKey};
use tokio::sync::Mutex;

use crate::verse_post_store::VersePostStore;

#[derive(Clone)]
pub struct VerseHost {
    inner: Arc<Mutex<VerseHostInner>>,
    /// Phase 1.5.D persistent (in-memory for now) per-verse post log.
    /// Shared by-value with this `VerseHost` clone, so a handler that
    /// has a `VerseHost` can insert + retract without grabbing the
    /// inner-state mutex.
    posts: VersePostStore,
}

pub(crate) struct VerseHostInner {
    pub verse_key: SideKey,
    pub contract: ContractObject,
    pub content_key: VerseContentKey,
    pub members: HashSet<[u8; PUBLIC_KEY_LEN]>,
    /// Per-member contract version they have consented to. A member joining
    /// under v1 enters here as `(side, 1)`; after `VerseReconsent` for v2
    /// the entry becomes `(side, 2)`. Posts under a contract version the
    /// sender hasn't consented to are dropped.
    pub consented_versions: HashMap<[u8; PUBLIC_KEY_LEN], u64>,
    /// Live gossip-style map of (member side) → QUIC connection. Used to
    /// fan out posts and to push rotated content keys.
    pub active_sessions: HashMap<[u8; PUBLIC_KEY_LEN], quinn::Connection>,
    /// Audit P1.D — pending key-rotation pushes that failed delivery
    /// (member offline, transient stream error). On the next inbound
    /// contact from the member, the host re-pushes the stashed envelope
    /// so the member doesn't silently miss the rotated content key.
    /// Map is keyed by member side pubkey; the value is the latest
    /// `JoinAccept`-shaped envelope carrying the sealed rotated key.
    pub pending_key_pushes: HashMap<[u8; PUBLIC_KEY_LEN], Envelope>,
}

impl VerseHost {
    pub fn new(verse_key: SideKey, contract: ContractObject, content_key: VerseContentKey) -> Self {
        Self {
            inner: Arc::new(Mutex::new(VerseHostInner {
                verse_key,
                contract,
                content_key,
                members: HashSet::new(),
                consented_versions: HashMap::new(),
                active_sessions: HashMap::new(),
                pending_key_pushes: HashMap::new(),
            })),
            posts: VersePostStore::new(),
        }
    }

    /// Audit P1.D — stash a key-rotation envelope that failed to deliver.
    /// Replaces any earlier pending push for the same member, so members
    /// always get the latest sealed key on reconnect (not a stale one).
    pub async fn stash_pending_key_push(&self, member: [u8; PUBLIC_KEY_LEN], env: Envelope) {
        let mut g = self.inner.lock().await;
        g.pending_key_pushes.insert(member, env);
    }

    /// Audit P1.D — take any pending key-rotation envelope for a member.
    /// Called when a member reconnects so we can deliver the stashed
    /// push on the new connection. Idempotent: returns `None` if there
    /// is nothing pending.
    pub async fn take_pending_key_push(&self, member: &[u8; PUBLIC_KEY_LEN]) -> Option<Envelope> {
        self.inner.lock().await.pending_key_pushes.remove(member)
    }

    /// Test / diagnostic helper: count pending pushes.
    pub async fn pending_key_push_count(&self) -> usize {
        self.inner.lock().await.pending_key_pushes.len()
    }

    /// Handle to the per-verse post store (Phase 1.5.D).
    pub fn posts(&self) -> VersePostStore {
        self.posts.clone()
    }

    /// Snapshot the verse's current member pubkeys. Used by the
    /// desktop client's "Group members" UI when this node is the
    /// verse's moderator (only moderators have an authoritative
    /// member list — plain members learn each other through posts).
    pub async fn members(&self) -> Vec<[u8; PUBLIC_KEY_LEN]> {
        let g = self.inner.lock().await;
        g.members.iter().copied().collect()
    }

    /// Phase 3 Stage D — add a member to a locally-hosted verse without
    /// running the JoinRequest/Accept QUIC round-trip. Used when the
    /// moderator (who hosts the verse) "joins" their own verse on
    /// create_group; avoids dialing yourself over loopback for a flow
    /// that has no remote semantics. Returns the issued MembershipToken
    /// wire bytes + the verse's content-key bytes — the same two
    /// pieces a remote member receives via JoinAccept. The caller is
    /// expected to persist these (via SideStore::upsert_verse_membership)
    /// so the moderator's session can post + restart-rehydrate.
    pub async fn add_local_member(
        &self,
        member_side: [u8; PUBLIC_KEY_LEN],
        issued_at: u64,
    ) -> sidevers_core::Result<(Vec<u8>, [u8; 32])> {
        let mut g = self.inner.lock().await;
        g.members.insert(member_side);
        let version = g.contract.version;
        g.consented_versions.insert(member_side, version);
        let contract_hash = g.contract.hash();
        let token = sidevers_core::verse::MembershipToken::sign(
            &g.verse_key,
            contract_hash,
            member_side,
            issued_at,
        )?;
        let token_bytes = token.to_wire_bytes();
        let content_key_bytes = *g.content_key.as_bytes();
        Ok((token_bytes, content_key_bytes))
    }

    pub(crate) async fn with<R>(&self, f: impl FnOnce(&VerseHostInner) -> R) -> R {
        let guard = self.inner.lock().await;
        f(&guard)
    }

    pub(crate) async fn with_mut<R>(&self, f: impl FnOnce(&mut VerseHostInner) -> R) -> R {
        let mut guard = self.inner.lock().await;
        f(&mut guard)
    }

    pub async fn contract(&self) -> ContractObject {
        self.inner.lock().await.contract.clone()
    }

    pub async fn member_count(&self) -> usize {
        self.inner.lock().await.members.len()
    }

    pub async fn is_member(&self, side: &[u8; PUBLIC_KEY_LEN]) -> bool {
        self.inner.lock().await.members.contains(side)
    }

    /// Generate a fresh `VerseContentKey` and replace the current one.
    /// The old key is dropped — callers MUST distribute the new key to
    /// remaining members (via a JoinAccept-shaped push) before the next post
    /// or those posts will be unreadable.
    pub async fn rotate_content_key(&self) -> sidevers_core::Result<VerseContentKey> {
        let new_key = VerseContentKey::generate()?;
        let mut guard = self.inner.lock().await;
        let key_bytes = *new_key.as_bytes();
        guard.content_key = new_key;
        Ok(VerseContentKey::from_bytes(key_bytes))
    }

    /// Replace the current contract with a new one. Members keep their
    /// previously-consented version until they re-consent via VerseReconsent.
    pub async fn amend_contract(&self, new_contract: ContractObject) {
        let mut guard = self.inner.lock().await;
        guard.contract = new_contract;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sidevers_core::MessageType;
    use sidevers_core::envelope::{now_unix_seconds, random_nonce};
    use sidevers_core::keys::MasterKey;
    use sidevers_core::verse::ContractObject;

    fn fresh_host() -> VerseHost {
        let master = MasterKey::generate().unwrap();
        let verse_key = master.derive_side(&"test-verse".into()).unwrap();
        let contract = ContractObject::sign(
            &verse_key,
            1,
            "test",
            "",
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            now_unix_seconds().unwrap(),
        )
        .unwrap();
        let content_key = VerseContentKey::generate().unwrap();
        VerseHost::new(verse_key, contract, content_key)
    }

    fn dummy_envelope() -> Envelope {
        let m = MasterKey::generate().unwrap();
        let s = m.derive_side(&"signer".into()).unwrap();
        Envelope::sign_with(
            MessageType::JOIN_ACCEPT,
            &s,
            None,
            b"stashed-payload".to_vec(),
            now_unix_seconds().unwrap(),
            random_nonce().unwrap(),
        )
        .unwrap()
    }

    // Audit P1.D — stash + take round-trip.
    #[tokio::test]
    async fn pending_key_push_round_trip() {
        let host = fresh_host();
        let member = [0xAAu8; 32];
        assert_eq!(host.pending_key_push_count().await, 0);

        let env = dummy_envelope();
        host.stash_pending_key_push(member, env.clone()).await;
        assert_eq!(host.pending_key_push_count().await, 1);

        let taken = host.take_pending_key_push(&member).await.unwrap();
        assert_eq!(taken.nonce, env.nonce);
        // Pending count drops back to zero after take.
        assert_eq!(host.pending_key_push_count().await, 0);
        // Second take is None.
        assert!(host.take_pending_key_push(&member).await.is_none());
    }

    // Audit P1.D — a later stash overwrites earlier; members get the
    // latest rotated key on reconnect, not a stale one.
    #[tokio::test]
    async fn later_stash_supersedes_earlier() {
        let host = fresh_host();
        let member = [0xBBu8; 32];
        let env_old = dummy_envelope();
        let env_new = dummy_envelope();
        assert_ne!(env_old.nonce, env_new.nonce);

        host.stash_pending_key_push(member, env_old).await;
        host.stash_pending_key_push(member, env_new.clone()).await;
        // Only one entry; it's the newer one.
        assert_eq!(host.pending_key_push_count().await, 1);
        let taken = host.take_pending_key_push(&member).await.unwrap();
        assert_eq!(taken.nonce, env_new.nonce);
    }

    // Audit P1.D — multiple members each get their own stash slot.
    #[tokio::test]
    async fn distinct_members_have_separate_stashes() {
        let host = fresh_host();
        let m1 = [0x11u8; 32];
        let m2 = [0x22u8; 32];
        host.stash_pending_key_push(m1, dummy_envelope()).await;
        host.stash_pending_key_push(m2, dummy_envelope()).await;
        assert_eq!(host.pending_key_push_count().await, 2);
        assert!(host.take_pending_key_push(&m1).await.is_some());
        assert_eq!(host.pending_key_push_count().await, 1);
        assert!(host.take_pending_key_push(&m2).await.is_some());
        assert_eq!(host.pending_key_push_count().await, 0);
    }
}
