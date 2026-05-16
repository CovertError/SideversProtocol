//! Phase 1.5.D: per-verse persistent post log + retract execution.
//!
//! Pre-1.5.D the verse host forwarded posts straight through the
//! `verse_post_tx` channel without retaining them — so `DataDisposition::Retract`
//! had nothing to act on once the post had already drained. This store
//! retains the *sealed* per-post payload alongside its envelope metadata,
//! keyed by `(verse, author, nonce)`. On a `VERSE_LEAVE` with disposition
//! `Retract`, the host calls `retract_by_author` and every post that
//! member ever made is removed.
//!
//! Storage is in-memory in this iteration; the API is shaped so a
//! SQLite-backed implementation can drop in without changing call
//! sites (Phase 2 work).

use std::collections::HashMap;
use std::sync::Arc;

use sidevers_core::Envelope;
use sidevers_core::keys::PUBLIC_KEY_LEN;
use tokio::sync::Mutex;

/// One stored verse post.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredVersePost {
    pub envelope: Envelope,
    /// Sealed (not plaintext) payload as received on the wire.
    pub sealed_payload: Vec<u8>,
    pub stored_at: u64,
}

#[derive(Default)]
struct Inner {
    /// `verse -> author -> Vec<post>` so retracting an author is O(N)
    /// over only their own posts, not the whole verse log.
    posts: HashMap<[u8; PUBLIC_KEY_LEN], HashMap<[u8; PUBLIC_KEY_LEN], Vec<StoredVersePost>>>,
}

/// Cheap clonable handle to the per-verse post log.
#[derive(Clone, Default)]
pub struct VersePostStore {
    inner: Arc<Mutex<Inner>>,
}

impl VersePostStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a post for `verse` made by `author`. Deduplicates on
    /// `(author, envelope.nonce)` so a retransmit (e.g. via gossip
    /// fanout) doesn't double-count.
    pub async fn insert(
        &self,
        verse: [u8; PUBLIC_KEY_LEN],
        author: [u8; PUBLIC_KEY_LEN],
        envelope: Envelope,
        sealed_payload: Vec<u8>,
        stored_at: u64,
    ) {
        let mut g = self.inner.lock().await;
        let by_author = g.posts.entry(verse).or_default();
        let bucket = by_author.entry(author).or_default();
        if bucket.iter().any(|p| p.envelope.nonce == envelope.nonce) {
            return;
        }
        bucket.push(StoredVersePost {
            envelope,
            sealed_payload,
            stored_at,
        });
    }

    /// Drop every post by `author` in `verse`. Returns the number of
    /// posts retracted.
    pub async fn retract_by_author(
        &self,
        verse: &[u8; PUBLIC_KEY_LEN],
        author: &[u8; PUBLIC_KEY_LEN],
    ) -> usize {
        let mut g = self.inner.lock().await;
        let Some(by_author) = g.posts.get_mut(verse) else {
            return 0;
        };
        by_author.remove(author).map(|v| v.len()).unwrap_or(0)
    }

    /// Snapshot all posts in `verse`, newest-stored-first.
    pub async fn list_verse(&self, verse: &[u8; PUBLIC_KEY_LEN]) -> Vec<StoredVersePost> {
        let g = self.inner.lock().await;
        let Some(by_author) = g.posts.get(verse) else {
            return Vec::new();
        };
        let mut out: Vec<StoredVersePost> =
            by_author.values().flat_map(|v| v.iter().cloned()).collect();
        out.sort_by_key(|p| std::cmp::Reverse(p.stored_at));
        out
    }

    /// Count of posts currently held for `verse`.
    pub async fn len(&self, verse: &[u8; PUBLIC_KEY_LEN]) -> usize {
        let g = self.inner.lock().await;
        g.posts
            .get(verse)
            .map(|by_author| by_author.values().map(|v| v.len()).sum::<usize>())
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sidevers_core::MessageType;
    use sidevers_core::envelope::random_nonce;
    use sidevers_core::keys::{MasterKey, SideKey};

    fn fixture_side(seed: u8) -> SideKey {
        let m = MasterKey::from_seed(&[seed; 32]);
        m.derive_side(&"verse".into()).unwrap()
    }

    fn fixture_env(from: &SideKey, payload: Vec<u8>) -> Envelope {
        Envelope::sign_with(
            MessageType::VERSE_POST,
            from,
            None,
            payload,
            1_700_000_000,
            random_nonce().unwrap(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn insert_then_list_returns_post() {
        let s = VersePostStore::new();
        let verse = [0x11; 32];
        let author = fixture_side(0x22);
        let env = fixture_env(&author, b"hello".to_vec());
        s.insert(
            verse,
            author.public_bytes(),
            env.clone(),
            b"sealed-ct".to_vec(),
            1_700_000_001,
        )
        .await;
        let listed = s.list_verse(&verse).await;
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].sealed_payload, b"sealed-ct");
    }

    #[tokio::test]
    async fn insert_is_dedup_by_nonce() {
        let s = VersePostStore::new();
        let verse = [0x11; 32];
        let author = fixture_side(0x22);
        let env = fixture_env(&author, b"hello".to_vec());
        s.insert(
            verse,
            author.public_bytes(),
            env.clone(),
            b"sealed".to_vec(),
            1,
        )
        .await;
        s.insert(verse, author.public_bytes(), env, b"sealed".to_vec(), 2)
            .await;
        assert_eq!(s.len(&verse).await, 1);
    }

    #[tokio::test]
    async fn retract_by_author_drops_only_that_authors_posts() {
        let s = VersePostStore::new();
        let verse = [0xCC; 32];
        let alice = fixture_side(0xAA);
        let bob = fixture_side(0xBB);
        for i in 0..3 {
            let env = fixture_env(&alice, vec![i]);
            s.insert(
                verse,
                alice.public_bytes(),
                env,
                vec![i],
                1_700_000_000 + i as u64,
            )
            .await;
        }
        let env = fixture_env(&bob, b"bob-post".to_vec());
        s.insert(
            verse,
            bob.public_bytes(),
            env,
            b"bob-sealed".to_vec(),
            1_700_000_100,
        )
        .await;
        assert_eq!(s.len(&verse).await, 4);

        let removed = s.retract_by_author(&verse, &alice.public_bytes()).await;
        assert_eq!(removed, 3);
        // Bob's post survives.
        let listed = s.list_verse(&verse).await;
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].sealed_payload, b"bob-sealed");
    }

    #[tokio::test]
    async fn retract_unknown_author_is_noop() {
        let s = VersePostStore::new();
        let verse = [0x00; 32];
        let author = [0x99; 32];
        assert_eq!(s.retract_by_author(&verse, &author).await, 0);
    }
}
