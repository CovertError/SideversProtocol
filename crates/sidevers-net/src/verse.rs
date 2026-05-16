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
            })),
            posts: VersePostStore::new(),
        }
    }

    /// Handle to the per-verse post store (Phase 1.5.D).
    pub fn posts(&self) -> VersePostStore {
        self.posts.clone()
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
