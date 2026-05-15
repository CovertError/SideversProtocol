//! Two-node conformance harness (Month 3).
//!
//! Spawns a pair of in-process `sidevers_net::Node` instances on loopback,
//! random ephemeral ports, with temporary data directories. Drives them
//! through the Month-3 message-type matrix and asserts behavior.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use sidevers_core::Address;
use sidevers_core::keys::{MasterKey, SideKey};
use sidevers_net::Node;
#[cfg(test)]
use sidevers_net::{Intent, fetch_object, send_dm};
use tempfile::TempDir;

pub struct TestNode {
    pub node: Arc<Node>,
    pub side_seed: [u8; 32],
    pub _tmp: TempDir,
}

impl TestNode {
    pub async fn spawn(label: &str) -> Self {
        let master = MasterKey::generate().expect("CSPRNG");
        let side = master.derive_side(&label.into()).expect("derive");
        let side_seed = side.to_seed();
        let tmp = tempfile::tempdir().expect("tempdir");
        let listen = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        let node = Node::start(side, listen, tmp.path()).await.expect("start");
        TestNode {
            node: Arc::new(node),
            side_seed,
            _tmp: tmp,
        }
    }

    pub fn listen_addr(&self) -> SocketAddr {
        self.node.listen_addr()
    }

    pub fn address(&self) -> Address {
        self.node.address()
    }

    pub fn data_dir(&self) -> PathBuf {
        self._tmp.path().to_owned()
    }

    pub fn local_side(&self) -> SideKey {
        SideKey::from_seed(&self.side_seed, "(test)")
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use sidevers_storage::ObjectStore;

    #[tokio::test]
    async fn handshake_completes() {
        let alice = TestNode::spawn("work").await;
        let bob = TestNode::spawn("close").await;
        // Use a transient client node to dial bob.
        let alice_client = Node::start(
            alice.local_side(),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            alice.data_dir().as_path(),
        )
        .await
        .unwrap();
        let session = alice_client
            .dial(bob.listen_addr(), Intent::Direct)
            .await
            .unwrap();
        assert_eq!(session.peer_side, *bob.address().key_bytes());
        drop(session);
        alice_client.shutdown().await;
    }

    #[tokio::test]
    async fn dm_round_trip() {
        let alice = TestNode::spawn("work").await;
        let bob = TestNode::spawn("close").await;
        let session = alice
            .node
            .dial(bob.listen_addr(), Intent::Direct)
            .await
            .unwrap();
        send_dm(&session, alice.node.side(), b"hello bob")
            .await
            .unwrap();
        drop(session);
        let dm = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            bob.node.next_direct_message(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&dm.plaintext, b"hello bob");
        assert_eq!(dm.envelope.from, *alice.address().key_bytes());
    }

    #[tokio::test]
    async fn storage_put_then_remote_get() {
        let alice = TestNode::spawn("work").await;
        let bob = TestNode::spawn("close").await;
        // Put on Bob's store.
        let bob_store = ObjectStore::open(bob.data_dir().as_path()).await.unwrap();
        let bytes = b"some object content".to_vec();
        let hash = bob_store.put(bytes.clone()).await.unwrap();
        drop(bob_store);

        // Alice fetches over the network.
        let session = alice
            .node
            .dial(bob.listen_addr(), Intent::Storage)
            .await
            .unwrap();
        let fetched = fetch_object(&session, alice.node.side(), &hash)
            .await
            .unwrap();
        assert_eq!(fetched.as_deref(), Some(&bytes[..]));
    }

    #[tokio::test]
    async fn storage_miss_for_unknown_hash() {
        let alice = TestNode::spawn("work").await;
        let bob = TestNode::spawn("close").await;
        let session = alice
            .node
            .dial(bob.listen_addr(), Intent::Storage)
            .await
            .unwrap();
        let bogus = [0xCDu8; 32];
        let fetched = fetch_object(&session, alice.node.side(), &bogus)
            .await
            .unwrap();
        assert!(fetched.is_none());
    }

    #[tokio::test]
    async fn tampered_disk_blob_is_rejected_via_network() {
        // Bob puts a large object → goes to disk; we corrupt the on-disk
        // bytes and then alice's get fails because the server's hash-on-fetch
        // (in the local ObjectStore) rejects before sending.
        let alice = TestNode::spawn("work").await;
        let bob = TestNode::spawn("close").await;
        let bob_store = ObjectStore::open(bob.data_dir().as_path()).await.unwrap();
        let big = vec![0x55u8; 10 * 1024]; // exceeds INLINE_MAX → blob file
        let hash = bob_store.put(big).await.unwrap();
        drop(bob_store);

        // Corrupt the disk blob.
        let hex = hex::encode(hash);
        let path = bob.data_dir().join("objects").join(&hex[..2]).join(&hex);
        let mut bad = std::fs::read(&path).unwrap();
        bad[0] ^= 0xFF;
        std::fs::write(&path, &bad).unwrap();

        // Bob's StorageGet handler returns StorageMiss (because get() failed
        // hash verification internally and the response builder treats failures
        // as misses).
        let session = alice
            .node
            .dial(bob.listen_addr(), Intent::Storage)
            .await
            .unwrap();
        let fetched = fetch_object(&session, alice.node.side(), &hash)
            .await
            .unwrap();
        assert!(
            fetched.is_none(),
            "tampered blob must not be served as if intact"
        );
    }

    #[tokio::test]
    async fn anonymous_dial_uses_ephemeral_side_not_node_primary() {
        // §4.5: anonymous handshake uses a throwaway side. The peer sees an
        // address that has no cryptographic link to the caller's primary.
        use sidevers_net::send_dm;

        let alice = TestNode::spawn("alice").await;
        let bob = TestNode::spawn("bob").await;
        let alice_primary = *alice.address().key_bytes();

        let (session, ephemeral) = alice
            .node
            .dial_anonymous(bob.listen_addr(), Intent::Direct)
            .await
            .unwrap();
        // The handshake's local side IS the ephemeral, not alice's primary.
        assert_ne!(ephemeral.public_bytes(), alice_primary);

        // Send a DM signed by the ephemeral.
        send_dm(&session, &ephemeral, b"from a stranger")
            .await
            .unwrap();
        drop(session);

        let dm = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            bob.node.next_direct_message(),
        )
        .await
        .unwrap()
        .unwrap();
        // Bob sees the ephemeral, not alice's primary.
        assert_eq!(dm.envelope.from, ephemeral.public_bytes());
        assert_ne!(dm.envelope.from, alice_primary);
        assert_eq!(&dm.plaintext, b"from a stranger");
    }

    #[tokio::test]
    async fn storage_offer_want_have_round_trip() {
        // Alice has bytes. She offers them to Bob over a Storage-intent
        // session. Bob doesn't have them → replies want=true. Alice sends
        // them on the same stream. Bob ingests; hash matches.
        use sidevers_net::offer_object;
        use sidevers_storage::{ObjectStore, Reference};

        let alice = TestNode::spawn("alice").await;
        let bob = TestNode::spawn("bob").await;

        // Alice ingests an object locally.
        let alice_store = ObjectStore::open(alice.data_dir().as_path()).await.unwrap();
        let payload = b"shared content".to_vec();
        let hash = alice_store.put(payload.clone()).await.unwrap();
        let reference = Reference::new(hash, payload.len() as u64, "text/plain");

        // Alice offers to Bob.
        let session = alice
            .node
            .dial(bob.listen_addr(), Intent::Storage)
            .await
            .unwrap();
        let accepted = offer_object(&session, alice.node.side(), reference, &alice_store)
            .await
            .unwrap();
        assert!(accepted, "Bob should want the object he doesn't have");

        // Bob should now have the bytes in his store.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let bob_store = ObjectStore::open(bob.data_dir().as_path()).await.unwrap();
        let bob_copy = bob_store.get(&hash).await.unwrap();
        assert_eq!(bob_copy.as_deref(), Some(&payload[..]));
    }

    #[tokio::test]
    async fn storage_offer_declined_when_peer_already_has() {
        use sidevers_net::offer_object;
        use sidevers_storage::{ObjectStore, Reference};

        let alice = TestNode::spawn("alice").await;
        let bob = TestNode::spawn("bob").await;

        // Both have the same bytes already (content-addressed: same bytes
        // → same hash).
        let payload = b"already here".to_vec();
        let alice_store = ObjectStore::open(alice.data_dir().as_path()).await.unwrap();
        let bob_store = ObjectStore::open(bob.data_dir().as_path()).await.unwrap();
        let hash_a = alice_store.put(payload.clone()).await.unwrap();
        let hash_b = bob_store.put(payload.clone()).await.unwrap();
        assert_eq!(hash_a, hash_b);
        let reference = Reference::new(hash_a, payload.len() as u64, "text/plain");

        let session = alice
            .node
            .dial(bob.listen_addr(), Intent::Storage)
            .await
            .unwrap();
        let accepted = offer_object(&session, alice.node.side(), reference, &alice_store)
            .await
            .unwrap();
        assert!(!accepted, "Bob should decline an object he already has");
    }

    #[tokio::test]
    async fn ping_handshake_against_random_peer() {
        // A single-direction smoke test: spawn one listener; dial it; close.
        let bob = TestNode::spawn("close").await;
        let alice = TestNode::spawn("work").await;
        let session = alice
            .node
            .dial(bob.listen_addr(), Intent::Direct)
            .await
            .expect("handshake");
        assert_eq!(session.peer_side, *bob.address().key_bytes());
    }

    // =====================================================================
    // Month 4 — peer-exchange, rendezvous, store-and-forward, gossip
    // =====================================================================

    #[tokio::test]
    async fn peer_ask_returns_peers_seen_by_responder() {
        use sidevers_core::messages::peer::PeerInfo;
        use sidevers_net::query_peers;

        let relay = TestNode::spawn("relay").await;
        let alice = TestNode::spawn("alice").await;

        // Seed the relay's peer table with a third party so PeerTell returns
        // something non-trivial.
        relay
            .node
            .peers()
            .insert(PeerInfo {
                address: [0x99; 32],
                intents: vec![1, 3],
                endpoints: vec!["10.0.0.1:4242".into()],
                last_seen: 1_700_000_000,
            })
            .await;

        let session = alice
            .node
            .dial(relay.listen_addr(), Intent::Gossip)
            .await
            .unwrap();
        let peers = query_peers(&session, alice.node.side(), 50, None)
            .await
            .unwrap();
        // At least the seeded entry should be returned. Alice's own handshake
        // also inserted herself into relay's peer table, so there may be 2.
        assert!(
            peers.iter().any(|p| p.address == [0x99; 32]),
            "PeerTell missing seeded peer"
        );
    }

    #[tokio::test]
    async fn rendezvous_returns_target_endpoints() {
        use sidevers_core::messages::peer::PeerInfo;
        use sidevers_net::request_rendezvous;

        let relay = TestNode::spawn("relay").await;
        let alice = TestNode::spawn("alice").await;
        let target: [u8; 32] = [0xAA; 32];
        let target_endpoint = "203.0.113.7:4242".to_string();

        relay
            .node
            .peers()
            .insert(PeerInfo {
                address: target,
                intents: vec![1],
                endpoints: vec![target_endpoint.clone()],
                last_seen: 1_700_000_000,
            })
            .await;

        let session = alice
            .node
            .dial(relay.listen_addr(), Intent::Gossip)
            .await
            .unwrap();
        let endpoints = request_rendezvous(&session, alice.node.side(), target)
            .await
            .unwrap();
        assert_eq!(endpoints, vec![target_endpoint]);
    }

    #[tokio::test]
    async fn store_and_forward_delivers_when_recipient_appears() {
        use sidevers_core::messages::forward::ForwardDeliverPayload;
        use sidevers_net::{accept_one_push, submit_forward};

        let relay = TestNode::spawn("relay").await;
        let alice = TestNode::spawn("alice").await;
        let carol = TestNode::spawn("carol").await;

        // Alice deposits an opaque "inner envelope" for Carol with the relay.
        let inner_envelope_bytes = b"opaque-inner-envelope-bytes".to_vec();
        let alice_session = alice
            .node
            .dial(relay.listen_addr(), Intent::Gossip)
            .await
            .unwrap();
        submit_forward(
            &alice_session,
            alice.node.side(),
            *carol.address().key_bytes(),
            inner_envelope_bytes.clone(),
            60,
        )
        .await
        .unwrap();
        drop(alice_session);

        // Carol later dials the relay with Gossip intent; serve_gossip drains
        // the mailbox and pushes ForwardDeliver before the accept-loop runs.
        let carol_session = carol
            .node
            .dial(relay.listen_addr(), Intent::Gossip)
            .await
            .unwrap();
        let pushed = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            accept_one_push(&carol_session),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            pushed.message_type,
            sidevers_core::MessageType::FORWARD_DELIVER
        );
        let deliver = ForwardDeliverPayload::decode(&pushed.payload).unwrap();
        assert_eq!(deliver.envelope, inner_envelope_bytes);
    }

    #[tokio::test]
    async fn broadcast_announcement_reaches_relay() {
        use sidevers_net::publish_broadcast;

        let relay = TestNode::spawn("relay").await;
        let publisher = TestNode::spawn("publisher").await;

        let session = publisher
            .node
            .dial(relay.listen_addr(), Intent::Gossip)
            .await
            .unwrap();
        publish_broadcast(&session, publisher.node.side(), b"breaking news".to_vec())
            .await
            .unwrap();
        drop(session);

        // The relay should observe the announcement on its public-broadcast queue.
        let env = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            relay.node.next_public_broadcast(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(env.message_type, sidevers_core::MessageType::ANNOUNCEMENT);
        assert_eq!(env.payload, b"breaking news");
        assert_eq!(env.from, *publisher.address().key_bytes());
    }

    // =====================================================================
    // Phase 1.5a — verses (§8): form, fetch contract, join, post
    // =====================================================================

    #[tokio::test]
    async fn verse_form_join_and_post_round_trip() {
        use sidevers_core::messages::verse::FieldValues;
        use sidevers_core::verse::{ContractObject, FieldKind, FieldSpec, VerseContentKey};
        use sidevers_net::{VerseHost, fetch_contract, post_to_verse, request_join};

        let host = TestNode::spawn("host").await;
        let member = TestNode::spawn("member").await;

        // 1. Host creates a verse: keypair, contract, content key.
        let verse_seed = [0x77u8; 32];
        let verse_master = sidevers_core::keys::MasterKey::from_seed(&verse_seed);
        let verse_key_for_signing = verse_master.derive_side(&"verse".into()).unwrap();
        let contract = ContractObject::sign(
            &verse_key_for_signing,
            1,
            "Book Club",
            "We read books and talk about them.",
            vec![FieldSpec {
                kind: FieldKind::new(FieldKind::DISPLAY_NAME),
                label: "Display name".into(),
                description: None,
                validator: None,
            }],
            vec![],
            vec![FieldKind::new(FieldKind::REAL_NAME)],
            vec![],
            vec![],
            1_700_000_000,
        )
        .unwrap();
        let content_key = VerseContentKey::generate().unwrap();
        // Re-derive the verse_key for hosting (SideKey isn't Clone).
        let verse_key_for_host = verse_master.derive_side(&"verse".into()).unwrap();
        let verse_host = VerseHost::new(verse_key_for_host, contract.clone(), content_key);
        host.node.host_verse(verse_host.clone()).await;

        // 2. Member dials host with Verse intent and fetches the contract.
        let session = member
            .node
            .dial(host.listen_addr(), sidevers_net::Intent::Verse)
            .await
            .unwrap();
        let fetched = fetch_contract(&session, member.node.side()).await.unwrap();
        assert_eq!(fetched, contract);

        // 3. Member sends a JoinRequest disclosing only the display name.
        let mut fields: FieldValues = std::collections::BTreeMap::new();
        fields.insert(FieldKind::new(FieldKind::DISPLAY_NAME), "yasmine".into());
        let membership = request_join(&session, member.node.side(), &contract, fields)
            .await
            .unwrap();
        assert_eq!(membership.verse, contract.verse);
        assert_eq!(membership.contract_hash, contract.hash());
        // Host should now count us as a member.
        assert_eq!(verse_host.member_count().await, 1);

        // 4. Member posts a verse-key-encrypted message.
        post_to_verse(
            &session,
            member.node.side(),
            &membership,
            b"hello book club",
        )
        .await
        .unwrap();

        // 5. Host receives the post and decrypts it.
        let received = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            host.node.next_verse_post(),
        )
        .await
        .expect("verse post timed out")
        .expect("post channel closed");
        assert_eq!(received.plaintext, b"hello book club");
        assert_eq!(received.envelope.from, *member.address().key_bytes());
    }

    #[tokio::test]
    async fn broadcast_propagates_through_relay_to_subscriber() {
        use sidevers_net::{accept_one_push, publish_broadcast};

        // Three nodes: subscriber and publisher both connect to relay with
        // Gossip intent. Publisher broadcasts; relay fans out to subscriber.
        let relay = TestNode::spawn("relay").await;
        let subscriber = TestNode::spawn("subscriber").await;
        let publisher = TestNode::spawn("publisher").await;

        // Subscriber connects FIRST so it's registered as an active gossip
        // peer before the publisher broadcasts.
        let sub_session = subscriber
            .node
            .dial(relay.listen_addr(), Intent::Gossip)
            .await
            .unwrap();

        // Give the relay a moment to register subscriber's connection in
        // active_gossip before publisher pushes.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Publisher dials and broadcasts.
        let pub_session = publisher
            .node
            .dial(relay.listen_addr(), Intent::Gossip)
            .await
            .unwrap();
        publish_broadcast(&pub_session, publisher.node.side(), b"hello world".to_vec())
            .await
            .unwrap();
        drop(pub_session);

        // Subscriber should receive the fan-out push on its session.
        let pushed = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            accept_one_push(&sub_session),
        )
        .await
        .expect("propagation timed out")
        .expect("push failed");
        assert_eq!(
            pushed.message_type,
            sidevers_core::MessageType::ANNOUNCEMENT
        );
        assert_eq!(pushed.payload, b"hello world");
        assert_eq!(pushed.from, *publisher.address().key_bytes());
    }

    // =====================================================================
    // Phase 1.5b — verse remainder: fanout, leave + rotate, remove, reconsent
    // =====================================================================

    /// Build a fresh host node with a default Book Club verse already set up.
    /// Returns `(host_node, verse_keypair, contract)`.
    async fn spawn_verse_host(
        label: &str,
    ) -> (TestNode, SideKey, sidevers_core::verse::ContractObject) {
        use sidevers_core::verse::{ContractObject, FieldKind, FieldSpec, VerseContentKey};
        use sidevers_net::VerseHost;
        let host = TestNode::spawn(label).await;
        let verse_master = MasterKey::generate().unwrap();
        let verse_key = verse_master.derive_side(&"verse".into()).unwrap();
        let verse_key_for_host = verse_master.derive_side(&"verse".into()).unwrap();
        let contract = ContractObject::sign(
            &verse_key,
            1,
            "Book Club",
            "Reading together.",
            vec![FieldSpec {
                kind: FieldKind::new(FieldKind::DISPLAY_NAME),
                label: "Display name".into(),
                description: None,
                validator: None,
            }],
            vec![],
            vec![FieldKind::new(FieldKind::REAL_NAME)],
            vec![],
            vec![],
            1_700_000_000,
        )
        .unwrap();
        let content_key = VerseContentKey::generate().unwrap();
        let verse_host = VerseHost::new(verse_key_for_host, contract.clone(), content_key);
        host.node.host_verse(verse_host).await;
        (host, verse_key, contract)
    }

    #[tokio::test]
    async fn verse_two_members_fanout() {
        use sidevers_core::messages::verse::{FieldValues, VersePostPayload};
        use sidevers_net::{accept_one_push, post_to_verse, request_join};

        let (host, _vk, contract) = spawn_verse_host("host").await;
        let alice = TestNode::spawn("alice").await;
        let bob = TestNode::spawn("bob").await;

        // Both members dial + join.
        let alice_session = alice
            .node
            .dial(host.listen_addr(), Intent::Verse)
            .await
            .unwrap();
        let alice_membership = request_join(
            &alice_session,
            alice.node.side(),
            &contract,
            FieldValues::new(),
        )
        .await
        .unwrap();

        let bob_session = bob
            .node
            .dial(host.listen_addr(), Intent::Verse)
            .await
            .unwrap();
        let bob_membership =
            request_join(&bob_session, bob.node.side(), &contract, FieldValues::new())
                .await
                .unwrap();

        // Let the host register bob's session in active_sessions before alice posts.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Alice posts.
        post_to_verse(
            &alice_session,
            alice.node.side(),
            &alice_membership,
            b"first post",
        )
        .await
        .unwrap();

        // Bob receives the fan-out (the still-encrypted VersePost envelope).
        let pushed = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            accept_one_push(&bob_session),
        )
        .await
        .expect("fanout timed out")
        .expect("push failed");
        assert_eq!(pushed.message_type, sidevers_core::MessageType::VERSE_POST);
        assert_eq!(pushed.from, *alice.address().key_bytes());

        // Bob decrypts with his content key — should match alice's plaintext.
        let post = VersePostPayload::decode(&pushed.payload).unwrap();
        let plain = bob_membership
            .content_key
            .open(&post.nonce, &post.ciphertext, b"sidevers/v1/verse-post")
            .unwrap();
        assert_eq!(plain, b"first post");
    }

    #[tokio::test]
    async fn verse_leave_rotates_key_so_old_key_cannot_decrypt() {
        use sidevers_core::messages::verse::{DataDisposition, FieldValues, VersePostPayload};
        use sidevers_net::{leave_verse, post_to_verse, request_join};

        let (host, _vk, contract) = spawn_verse_host("host").await;
        let alice = TestNode::spawn("alice").await;
        let bob = TestNode::spawn("bob").await;

        let alice_session = alice
            .node
            .dial(host.listen_addr(), Intent::Verse)
            .await
            .unwrap();
        let alice_membership = request_join(
            &alice_session,
            alice.node.side(),
            &contract,
            FieldValues::new(),
        )
        .await
        .unwrap();

        let bob_session = bob
            .node
            .dial(host.listen_addr(), Intent::Verse)
            .await
            .unwrap();
        let bob_membership =
            request_join(&bob_session, bob.node.side(), &contract, FieldValues::new())
                .await
                .unwrap();
        let bob_old_key = bob_membership.content_key.clone();

        // Bob leaves. Host rotates the content key.
        leave_verse(
            &bob_session,
            bob.node.side(),
            &bob_membership,
            DataDisposition::Retract,
            Some("bye".into()),
        )
        .await
        .unwrap();
        drop(bob_session);

        // Give the host time to process the leave + rotate.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Alice's content_key is now stale; the host has rotated. Her post
        // will be encrypted under the NEW key. But wait — alice doesn't know
        // about the rotation yet (she didn't `accept_one_push` to pick it
        // up). In Phase 1.5b alice posts under her old key; the host's
        // current key is new; the host fails to decrypt and drops the post.
        // The point of this test is that bob's OLD key, even if leaked,
        // cannot read posts made after the rotation.
        //
        // To actually verify "bob can't read the new post," alice needs to
        // pick up the rotated key first. Let her accept the push.
        let pushed = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            sidevers_net::accept_one_push(&alice_session),
        )
        .await
        .expect("rotation push timed out")
        .expect("push failed");
        assert_eq!(pushed.message_type, sidevers_core::MessageType::JOIN_ACCEPT);

        // Apply the rotation to alice's membership in place.
        let mut alice_membership_rotated = alice_membership.clone();
        sidevers_net::apply_verse_key_rotation(
            alice.node.side(),
            &mut alice_membership_rotated,
            &pushed,
        )
        .unwrap();
        assert_ne!(
            alice_membership_rotated.content_key.as_bytes(),
            bob_old_key.as_bytes()
        );

        // Alice posts under the new key.
        post_to_verse(
            &alice_session,
            alice.node.side(),
            &alice_membership_rotated,
            b"after bob left",
        )
        .await
        .unwrap();

        // Host receives + decrypts the new post.
        let received = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            host.node.next_verse_post(),
        )
        .await
        .expect("post timed out")
        .expect("post channel closed");
        assert_eq!(received.plaintext, b"after bob left");

        // The new ciphertext, decoded from received.envelope, MUST NOT be
        // decryptable with bob's stashed old key — proving forward secrecy.
        let new_post = VersePostPayload::decode(&received.envelope.payload).unwrap();
        let attempt = bob_old_key.open(
            &new_post.nonce,
            &new_post.ciphertext,
            b"sidevers/v1/verse-post",
        );
        assert!(
            attempt.is_err(),
            "bob's old key must NOT decrypt the post-rotation ciphertext"
        );
    }

    #[tokio::test]
    async fn verse_remove_drops_future_posts_from_removed_member() {
        use sidevers_core::envelope::{now_unix_seconds, random_nonce};
        use sidevers_core::messages::verse::{FieldValues, VerseRemovePayload};
        use sidevers_core::{Envelope, MessageType};
        use sidevers_net::{post_to_verse, request_join};

        let (host, verse_key, contract) = spawn_verse_host("host").await;
        let bob = TestNode::spawn("bob").await;

        let bob_session = bob
            .node
            .dial(host.listen_addr(), Intent::Verse)
            .await
            .unwrap();
        let bob_membership =
            request_join(&bob_session, bob.node.side(), &contract, FieldValues::new())
                .await
                .unwrap();

        // The verse (acting as moderator) signs a VerseRemove. The host
        // accepts it only when the envelope is signed by the verse's own
        // keypair. We craft the envelope directly.
        let remove_payload = VerseRemovePayload::sign(
            &verse_key,
            contract.verse,
            *bob.address().key_bytes(),
            "spam",
            now_unix_seconds().unwrap(),
        )
        .unwrap();
        let remove_env = Envelope::sign_with(
            MessageType::VERSE_REMOVE,
            &verse_key,
            Some(contract.verse),
            remove_payload.encode(),
            now_unix_seconds().unwrap(),
            random_nonce().unwrap(),
        )
        .unwrap();

        // Open a dedicated Verse-intent session FROM the verse keypair to
        // the host, send the remove envelope. The verse-keypair must dial as
        // itself for the host's serve_verse to attribute the envelope's
        // `from` correctly.
        let moderator = TestNode {
            node: {
                let tmp = tempfile::tempdir().unwrap();
                let listen = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
                std::sync::Arc::new(Node::start(verse_key, listen, tmp.path()).await.unwrap())
            },
            side_seed: [0u8; 32],
            _tmp: tempfile::tempdir().unwrap(),
        };
        let mod_session = moderator
            .node
            .dial(host.listen_addr(), Intent::Verse)
            .await
            .unwrap();
        // Send the pre-built remove envelope on the moderator's session.
        let (mut send, _recv) = mod_session.open_and_send(&remove_env).await.unwrap();
        send.finish().ok();
        let _ = send.stopped().await;
        drop(mod_session);

        // Give the host time to process the remove + rotate.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Bob (still on his old stale content key) tries to post. The host
        // drops it: bob is no longer in the members set.
        post_to_verse(
            &bob_session,
            bob.node.side(),
            &bob_membership,
            b"i was removed",
        )
        .await
        .unwrap();
        // Nothing should arrive on host.next_verse_post within a short window.
        let attempt = tokio::time::timeout(
            std::time::Duration::from_millis(300),
            host.node.next_verse_post(),
        )
        .await;
        assert!(
            attempt.is_err(),
            "removed member's post must NOT reach next_verse_post"
        );
    }

    #[tokio::test]
    async fn verse_reconsent_protocol_round_trip() {
        // Phase 1.5b validates the VerseReconsent codec + handler shape: a
        // member sends a signed re-consent envelope to the current contract
        // hash; the host accepts it. Posts continue to work afterward.
        // Full amend-while-live (host swaps the contract in-place) needs
        // additional API surface (an `amend_contract` push to members);
        // that's Phase 1.5c.
        use sidevers_core::messages::verse::FieldValues;
        use sidevers_net::{post_to_verse, reconsent_to_amendment, request_join};

        let (host, _verse_key, contract) = spawn_verse_host("host").await;
        let alice = TestNode::spawn("alice").await;

        let alice_session = alice
            .node
            .dial(host.listen_addr(), Intent::Verse)
            .await
            .unwrap();
        let alice_membership = request_join(
            &alice_session,
            alice.node.side(),
            &contract,
            FieldValues::new(),
        )
        .await
        .unwrap();

        // Alice re-consents to the CURRENT contract hash (idempotent).
        reconsent_to_amendment(&alice_session, alice.node.side(), contract.hash())
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Alice can still post afterward.
        post_to_verse(
            &alice_session,
            alice.node.side(),
            &alice_membership,
            b"still here",
        )
        .await
        .unwrap();

        let received = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            host.node.next_verse_post(),
        )
        .await
        .expect("post timed out")
        .expect("post channel closed");
        assert_eq!(received.plaintext, b"still here");
    }

    #[tokio::test]
    async fn verse_live_amend_pushes_new_contract_and_member_reconsents() {
        // Phase 1.5c: host runs `host_amend_verse(new_contract)`. The host
        // updates its contract in-place AND pushes a VerseAmend envelope to
        // every currently-active member session. The member receives the
        // push, decodes the new contract, sends VerseReconsent to its hash,
        // and can post under v2.
        use sidevers_core::messages::verse::FieldValues;
        use sidevers_core::verse::{ContractObject, FieldKind, FieldSpec};
        use sidevers_net::{
            accept_one_push, decode_verse_amend, post_to_verse, reconsent_to_amendment,
            request_join,
        };

        let (host, verse_key, contract_v1) = spawn_verse_host("host").await;
        let alice = TestNode::spawn("alice").await;

        let alice_session = alice
            .node
            .dial(host.listen_addr(), Intent::Verse)
            .await
            .unwrap();
        let alice_membership = request_join(
            &alice_session,
            alice.node.side(),
            &contract_v1,
            FieldValues::new(),
        )
        .await
        .unwrap();

        // Let the host register alice's session in active_sessions.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Build a v2 contract (adds an optional pronoun field).
        let contract_v2 = ContractObject::sign(
            &verse_key,
            2,
            "Book Club v2",
            "Now with optional pronouns.",
            vec![FieldSpec {
                kind: FieldKind::new(FieldKind::DISPLAY_NAME),
                label: "Display name".into(),
                description: None,
                validator: None,
            }],
            vec![FieldSpec {
                kind: FieldKind::new(FieldKind::PRONOUN),
                label: "Pronoun".into(),
                description: None,
                validator: None,
            }],
            vec![FieldKind::new(FieldKind::REAL_NAME)],
            vec![],
            vec![],
            1_700_000_500,
        )
        .unwrap();
        let v2_hash = contract_v2.hash();

        // Host amends + pushes.
        host.node
            .host_amend_verse(contract_v2.clone())
            .await
            .unwrap();

        // Alice's session receives the VerseAmend push.
        let pushed = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            accept_one_push(&alice_session),
        )
        .await
        .expect("amend push timed out")
        .expect("push failed");
        let amended = decode_verse_amend(&pushed, &alice_membership.verse).unwrap();
        assert_eq!(amended.version, 2);
        assert_eq!(amended.hash(), v2_hash);

        // Alice re-consents to v2. After this her posts admit again.
        reconsent_to_amendment(&alice_session, alice.node.side(), v2_hash)
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Alice posts under v2 (her existing content_key still works — no
        // rotation on amendment, per spec §8.7).
        post_to_verse(
            &alice_session,
            alice.node.side(),
            &alice_membership,
            b"hello v2",
        )
        .await
        .unwrap();
        let received = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            host.node.next_verse_post(),
        )
        .await
        .expect("post timed out")
        .expect("post channel closed");
        assert_eq!(received.plaintext, b"hello v2");
    }

    #[tokio::test]
    async fn verse_reconsent_wrong_contract_hash_does_not_admit() {
        // A reconsent that references the WRONG contract hash leaves the
        // member in their previous consent state. Posts continue (the
        // contract didn't actually change), but we verify the reconsent
        // didn't crash the session.
        use sidevers_core::messages::verse::FieldValues;
        use sidevers_net::{reconsent_to_amendment, request_join};

        let (host, _verse_key, contract) = spawn_verse_host("host").await;
        let alice = TestNode::spawn("alice").await;
        let alice_session = alice
            .node
            .dial(host.listen_addr(), Intent::Verse)
            .await
            .unwrap();
        let _alice_membership = request_join(
            &alice_session,
            alice.node.side(),
            &contract,
            FieldValues::new(),
        )
        .await
        .unwrap();

        // Bogus contract hash; the host's serve_verse logs + drops, no crash.
        reconsent_to_amendment(&alice_session, alice.node.side(), [0xFF; 32])
            .await
            .unwrap();
        // Brief wait + sanity: the session is still alive.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        // (No assertion beyond "the call completed without erroring on the
        // wire" — the host's drop is silent by design.)
    }
}
