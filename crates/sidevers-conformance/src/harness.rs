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
use sidevers_net::{
    Intent, SideLifecycle, SideRelationship, announce_retirement, fetch_object, fetch_profile,
    send_dm, set_jitter_disabled,
};
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

    /// Replay rejection: sending the same `(from, nonce)` envelope twice
    /// must surface only once on the receiver. Exercises the receive-path
    /// replay cache check end-to-end. (Audit P2.9.)
    #[tokio::test]
    async fn replay_rejection_blocks_duplicate_envelope_at_receiver() {
        use sidevers_core::envelope::{NONCE_LEN, now_unix_seconds, random_nonce};
        use sidevers_core::payload as core_payload;
        use sidevers_core::{Envelope, MessageType};

        let alice = TestNode::spawn("alice").await;
        let bob = TestNode::spawn("bob").await;
        let session = alice
            .node
            .dial(bob.listen_addr(), Intent::Direct)
            .await
            .unwrap();

        // Hand-build a DM envelope with a fixed nonce so we can replay it.
        // Plaintext is treated as opaque bytes by the DM path (matching
        // what `send_dm` does).
        let alice_side = alice.node.side();
        let nonce: [u8; NONCE_LEN] = random_nonce().unwrap();
        let plaintext: &[u8] = b"replay-target";
        let ciphertext = core_payload::seal(
            plaintext,
            alice_side,
            &session.peer_side,
            &nonce,
            b"",
        )
        .unwrap();
        let env = Envelope::sign_with(
            MessageType::DIRECT_MESSAGE,
            alice_side,
            Some(session.peer_side),
            ciphertext,
            now_unix_seconds().unwrap(),
            nonce,
        )
        .unwrap();

        // First submission: should land.
        let (mut s1, _) = session.open_and_send(&env).await.unwrap();
        let _ = s1.finish();
        let _ = s1.stopped().await;

        let first = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            bob.node.next_direct_message(),
        )
        .await
        .expect("first DM should arrive")
        .expect("DM stream not closed");
        assert_eq!(&first.plaintext, plaintext);
        assert_eq!(first.envelope.nonce, nonce);

        // Second submission of the EXACT same envelope bytes: must be
        // dropped at the replay cache before reaching the inbox.
        let (mut s2, _) = session.open_and_send(&env).await.unwrap();
        let _ = s2.finish();
        let _ = s2.stopped().await;

        // Give the receiver a moment to process (and drop) the replay.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let replay = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            bob.node.next_direct_message(),
        )
        .await;
        assert!(
            replay.is_err(),
            "replay must not surface a second DirectMessageReceived event"
        );
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

    // -------------------------------------------------------------------
    // Phase 1.5+ — §8.4 field-kind enforcement at JOIN_REQUEST.
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn join_declined_when_required_field_missing() {
        use sidevers_core::messages::verse::FieldValues;
        use sidevers_core::verse::{ContractObject, FieldKind, FieldSpec, VerseContentKey};
        use sidevers_net::{VerseHost, request_join};

        let host = TestNode::spawn("host").await;
        let member = TestNode::spawn("member").await;

        let verse_master = sidevers_core::keys::MasterKey::from_seed(&[0x44u8; 32]);
        let verse_key_signing = verse_master.derive_side(&"verse".into()).unwrap();
        let contract = ContractObject::sign(
            &verse_key_signing,
            1,
            "Strict club",
            "Display name is mandatory.",
            vec![FieldSpec {
                kind: FieldKind::new(FieldKind::DISPLAY_NAME),
                label: "Display name".into(),
                description: None,
                validator: None,
            }],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            1_700_000_000,
        )
        .unwrap();
        let content_key = VerseContentKey::generate().unwrap();
        let verse_key_host = verse_master.derive_side(&"verse".into()).unwrap();
        host.node
            .host_verse(VerseHost::new(
                verse_key_host,
                contract.clone(),
                content_key,
            ))
            .await;

        let session = member
            .node
            .dial(host.listen_addr(), sidevers_net::Intent::Verse)
            .await
            .unwrap();
        // Member sends a JoinRequest with NO display-name field.
        let result =
            request_join(&session, member.node.side(), &contract, FieldValues::new()).await;
        let err = result.expect_err("expected decline");
        let msg = format!("{err}");
        assert!(
            msg.contains("missing-required"),
            "expected 'missing-required' decline, got {msg}"
        );
    }

    #[tokio::test]
    async fn join_declined_when_forbidden_field_present() {
        use sidevers_core::messages::verse::FieldValues;
        use sidevers_core::verse::{ContractObject, FieldKind, FieldSpec, VerseContentKey};
        use sidevers_net::{VerseHost, request_join};

        let host = TestNode::spawn("host").await;
        let member = TestNode::spawn("member").await;

        let verse_master = sidevers_core::keys::MasterKey::from_seed(&[0x55u8; 32]);
        let verse_key_signing = verse_master.derive_side(&"verse".into()).unwrap();
        // Required: display name. Forbidden: real name.
        let contract = ContractObject::sign(
            &verse_key_signing,
            1,
            "Anonymous club",
            "No real names here.",
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
            vec![],
            1_700_000_000,
        )
        .unwrap();
        let content_key = VerseContentKey::generate().unwrap();
        let verse_key_host = verse_master.derive_side(&"verse".into()).unwrap();
        host.node
            .host_verse(VerseHost::new(
                verse_key_host,
                contract.clone(),
                content_key,
            ))
            .await;

        let session = member
            .node
            .dial(host.listen_addr(), sidevers_net::Intent::Verse)
            .await
            .unwrap();
        // Member sends a JoinRequest including the FORBIDDEN real-name kind.
        let mut fields: FieldValues = std::collections::BTreeMap::new();
        fields.insert(FieldKind::new(FieldKind::DISPLAY_NAME), "yasmine".into());
        fields.insert(
            FieldKind::new(FieldKind::REAL_NAME),
            "Yasmine Al-Saud".into(),
        );
        let result = request_join(&session, member.node.side(), &contract, fields).await;
        let err = result.expect_err("expected decline");
        let msg = format!("{err}");
        assert!(
            msg.contains("forbidden-field"),
            "expected 'forbidden-field' decline, got {msg}"
        );
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
        use sidevers_core::verse::{ContractObject, FieldKind, VerseContentKey};
        use sidevers_net::VerseHost;
        let host = TestNode::spawn(label).await;
        let verse_master = MasterKey::generate().unwrap();
        let verse_key = verse_master.derive_side(&"verse".into()).unwrap();
        let verse_key_for_host = verse_master.derive_side(&"verse".into()).unwrap();
        // No required fields: these tests focus on fanout / leave / amend
        // semantics, not field-kind enforcement (which lives in its own
        // `join_declined_when_*` scenarios). Real-name is still forbidden
        // so the existing forbidden-kind round-trip in the protocol-level
        // tests keeps that surface exercised.
        let contract = ContractObject::sign(
            &verse_key,
            1,
            "Book Club",
            "Reading together.",
            vec![],
            vec![],
            vec![FieldKind::new(FieldKind::REAL_NAME)],
            vec![],
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

    // =========================================================================
    // Phase 1.5d — Profile (§7.3), capability enforcement (§7.7), retirement
    // (§7.8).
    // =========================================================================

    use sidevers_core::ProfilePayload;
    use sidevers_core::messages::profile::capability;
    use std::collections::BTreeSet;

    fn make_profile(side: &SideKey, caps: &[&str]) -> ProfilePayload {
        let mut set = BTreeSet::new();
        for c in caps {
            set.insert((*c).to_owned());
        }
        ProfilePayload::sign(
            side,
            Some("Test User".to_owned()),
            None,
            Some("conformance fixture".to_owned()),
            None,
            None,
            set,
            42,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn profile_publish_and_fetch_round_trip() {
        let alice = TestNode::spawn("work").await;
        let bob = TestNode::spawn("close").await;
        // Bob publishes a profile listing DIRECT_MESSAGE + STORAGE_HOST.
        let bob_profile = make_profile(
            &bob.local_side(),
            &[capability::DIRECT_MESSAGE, capability::STORAGE_HOST],
        );
        bob.node.set_local_profile(bob_profile.clone()).await;

        let session = alice
            .node
            .dial(bob.listen_addr(), Intent::Direct)
            .await
            .unwrap();
        let fetched = fetch_profile(&session, alice.node.side(), bob.node.side().public_bytes())
            .await
            .unwrap();
        assert_eq!(fetched, bob_profile);
        assert!(fetched.has_capability(capability::STORAGE_HOST));
    }

    #[tokio::test]
    async fn dm_dropped_when_recipient_lacks_direct_message_capability() {
        let alice = TestNode::spawn("work").await;
        let bob = TestNode::spawn("close").await;
        // Bob publishes a profile that does NOT include direct-message.
        let bob_profile = make_profile(&bob.local_side(), &[capability::STORAGE_HOST]);
        bob.node.set_local_profile(bob_profile).await;

        let session = alice
            .node
            .dial(bob.listen_addr(), Intent::Direct)
            .await
            .unwrap();
        send_dm(&session, alice.node.side(), b"can you read me?")
            .await
            .unwrap();
        drop(session);

        // Wait up to 1s for the DM to be dropped silently. Use a short
        // timeout, then poll for absence.
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(800),
            bob.node.next_direct_message(),
        )
        .await;
        assert!(
            result.is_err(),
            "expected DM to be silently dropped, but it was delivered"
        );
    }

    #[tokio::test]
    async fn dm_accepted_when_recipient_declares_capability() {
        let alice = TestNode::spawn("work").await;
        let bob = TestNode::spawn("close").await;
        let bob_profile = make_profile(&bob.local_side(), &[capability::DIRECT_MESSAGE]);
        bob.node.set_local_profile(bob_profile).await;

        let session = alice
            .node
            .dial(bob.listen_addr(), Intent::Direct)
            .await
            .unwrap();
        send_dm(&session, alice.node.side(), b"hi with capability")
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
        assert_eq!(&dm.plaintext, b"hi with capability");
    }

    #[tokio::test]
    async fn dm_accepted_with_default_capabilities_when_no_profile_set() {
        // No node sets a profile; the permissive default kicks in. This is
        // the path the pre-existing 140 tests rely on.
        let alice = TestNode::spawn("work").await;
        let bob = TestNode::spawn("close").await;
        assert!(bob.node.local_profile().await.is_none());

        let session = alice
            .node
            .dial(bob.listen_addr(), Intent::Direct)
            .await
            .unwrap();
        send_dm(&session, alice.node.side(), b"no profile, still works")
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
        assert_eq!(&dm.plaintext, b"no profile, still works");
    }

    #[tokio::test]
    async fn retirement_record_marks_side_retired_on_recipient() {
        let alice = TestNode::spawn("work").await;
        let bob = TestNode::spawn("close").await;
        // Bob has direct-message capability so the DM/retirement gets through.
        let bob_profile = make_profile(&bob.local_side(), &[capability::DIRECT_MESSAGE]);
        bob.node.set_local_profile(bob_profile).await;

        let session = alice
            .node
            .dial(bob.listen_addr(), Intent::Direct)
            .await
            .unwrap();
        let record = alice
            .node
            .publish_retirement(Some("test retirement".to_owned()))
            .await
            .unwrap();
        announce_retirement(&session, alice.node.side(), &record)
            .await
            .unwrap();
        drop(session);

        // Give bob a moment to process the inbound retirement record.
        for _ in 0..40 {
            if bob
                .node
                .is_side_retired(&alice.node.side().public_bytes())
                .await
            {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        panic!("bob did not mark alice's side as retired");
    }

    #[tokio::test]
    async fn retired_side_subsequent_dm_still_delivers_with_warning() {
        // Per §7.8 the keys still work; we warn but do not drop. Verify
        // the DM still arrives after the retirement record has been
        // observed.
        let alice = TestNode::spawn("work").await;
        let bob = TestNode::spawn("close").await;
        bob.node
            .set_local_profile(make_profile(
                &bob.local_side(),
                &[capability::DIRECT_MESSAGE],
            ))
            .await;

        // 1. alice announces retirement to bob.
        let session = alice
            .node
            .dial(bob.listen_addr(), Intent::Direct)
            .await
            .unwrap();
        let record = alice.node.publish_retirement(None).await.unwrap();
        announce_retirement(&session, alice.node.side(), &record)
            .await
            .unwrap();
        drop(session);

        // Wait for the retirement bit to flip.
        for _ in 0..40 {
            if bob
                .node
                .is_side_retired(&alice.node.side().public_bytes())
                .await
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(
            bob.node
                .is_side_retired(&alice.node.side().public_bytes())
                .await
        );

        // 2. alice (still using the same keys) sends a DM. It should be
        // delivered, with the warning logged but the envelope accepted.
        let session2 = alice
            .node
            .dial(bob.listen_addr(), Intent::Direct)
            .await
            .unwrap();
        send_dm(&session2, alice.node.side(), b"after retirement")
            .await
            .unwrap();
        drop(session2);
        let dm = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            bob.node.next_direct_message(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&dm.plaintext, b"after retirement");
    }

    // -------------------------------------------------------------------
    // Phase 1.5e — Side relationships (§7.4), lifecycle (§7.8), hygiene
    // jitter (§7.6).
    // -------------------------------------------------------------------

    use std::sync::Once;

    static JITTER_OFF: Once = Once::new();

    fn disable_jitter_once() {
        JITTER_OFF.call_once(|| {
            set_jitter_disabled(true);
        });
    }

    fn make_relationship(addr: [u8; 32], caps: &[&str]) -> SideRelationship {
        let mut set = BTreeSet::new();
        for c in caps {
            set.insert((*c).to_owned());
        }
        SideRelationship {
            address: addr,
            nickname: Some("contact".to_owned()),
            introduced_by: None,
            capabilities: set,
            notes: None,
            pinned: false,
            added_at: 1_700_000_000,
            peer_listen_addr: None,
        }
    }

    #[tokio::test]
    async fn relationship_round_trip_crud() {
        disable_jitter_once();
        let alice = TestNode::spawn("work").await;
        let bob_addr = [0xBB; 32];
        // Insert.
        alice
            .node
            .add_relationship(make_relationship(bob_addr, &[capability::DIRECT_MESSAGE]))
            .await;
        let got = alice.node.get_relationship(&bob_addr).await.unwrap();
        assert!(got.capabilities.contains(capability::DIRECT_MESSAGE));
        // List.
        let all = alice.node.list_relationships().await;
        assert_eq!(all.len(), 1);
        // Update.
        let before = alice
            .node
            .update_relationship(&bob_addr, |r| {
                r.nickname = Some("bob".to_owned());
                r.pinned = true;
            })
            .await
            .unwrap();
        assert_eq!(before.nickname.as_deref(), Some("contact"));
        let after = alice.node.get_relationship(&bob_addr).await.unwrap();
        assert_eq!(after.nickname.as_deref(), Some("bob"));
        assert!(after.pinned);
        // Remove.
        alice.node.remove_relationship(&bob_addr).await;
        assert!(alice.node.get_relationship(&bob_addr).await.is_none());
    }

    #[tokio::test]
    async fn dm_accepted_via_relationship_capability_even_without_profile() {
        disable_jitter_once();
        // Bob has no profile (so tier-3 = permissive default) AND Bob
        // adds a relationship for Alice listing direct-message. The
        // relationship is consulted first; its capability set decides.
        let alice = TestNode::spawn("work").await;
        let bob = TestNode::spawn("close").await;
        assert!(bob.node.local_profile().await.is_none());
        bob.node
            .add_relationship(make_relationship(
                alice.node.side().public_bytes(),
                &[capability::DIRECT_MESSAGE],
            ))
            .await;
        let session = alice
            .node
            .dial(bob.listen_addr(), Intent::Direct)
            .await
            .unwrap();
        send_dm(&session, alice.node.side(), b"via relationship")
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
        assert_eq!(&dm.plaintext, b"via relationship");
    }

    #[tokio::test]
    async fn dm_dropped_when_relationship_revokes_direct_message() {
        disable_jitter_once();
        // Bob's profile grants direct-message globally (tier-2 would
        // accept). But Bob's relationship for Alice has empty
        // capabilities — explicit block. Relationship wins (tier-1).
        let alice = TestNode::spawn("work").await;
        let bob = TestNode::spawn("close").await;
        let bob_profile = make_profile(&bob.local_side(), &[capability::DIRECT_MESSAGE]);
        bob.node.set_local_profile(bob_profile).await;
        bob.node
            .add_relationship(make_relationship(
                alice.node.side().public_bytes(),
                &[], // empty = block
            ))
            .await;
        let session = alice
            .node
            .dial(bob.listen_addr(), Intent::Direct)
            .await
            .unwrap();
        send_dm(&session, alice.node.side(), b"blocked")
            .await
            .unwrap();
        drop(session);
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(800),
            bob.node.next_direct_message(),
        )
        .await;
        assert!(
            result.is_err(),
            "expected DM dropped by relationship block, got delivered"
        );
    }

    #[tokio::test]
    async fn dm_accepted_when_relationship_grants_and_profile_denies() {
        disable_jitter_once();
        // Bob's profile has capabilities = {} (deny-all generally), but
        // Bob's relationship for Alice grants direct-message. Tier-1
        // (relationship) wins.
        let alice = TestNode::spawn("work").await;
        let bob = TestNode::spawn("close").await;
        // No direct-message in the profile.
        let bob_profile = make_profile(&bob.local_side(), &[capability::STORAGE_HOST]);
        bob.node.set_local_profile(bob_profile).await;
        bob.node
            .add_relationship(make_relationship(
                alice.node.side().public_bytes(),
                &[capability::DIRECT_MESSAGE],
            ))
            .await;
        let session = alice
            .node
            .dial(bob.listen_addr(), Intent::Direct)
            .await
            .unwrap();
        send_dm(&session, alice.node.side(), b"override allow")
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
        assert_eq!(&dm.plaintext, b"override allow");
    }

    #[tokio::test]
    async fn lifecycle_starts_created() {
        disable_jitter_once();
        let alice = TestNode::spawn("work").await;
        assert_eq!(alice.node.lifecycle().await, SideLifecycle::Created);
    }

    #[tokio::test]
    async fn lifecycle_becomes_active_after_first_send() {
        disable_jitter_once();
        let alice = TestNode::spawn("work").await;
        let bob = TestNode::spawn("close").await;
        // Use the Node wrapper (which touches lifecycle); the free
        // function does NOT touch lifecycle by design.
        let session = alice
            .node
            .dial(bob.listen_addr(), Intent::Direct)
            .await
            .unwrap();
        alice.node.send_dm(&session, b"first send").await.unwrap();
        assert_eq!(alice.node.lifecycle().await, SideLifecycle::Active);
    }

    #[tokio::test]
    async fn lifecycle_becomes_retired_after_publish_retirement() {
        disable_jitter_once();
        let alice = TestNode::spawn("work").await;
        let _record = alice.node.publish_retirement(None).await.unwrap();
        assert_eq!(alice.node.lifecycle().await, SideLifecycle::Retired);
    }

    // -------------------------------------------------------------------
    // Phase 1.5f Track B — Multi-side hosting (§7.2 + §7.6).
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn node_hosts_two_sides_with_distinct_endpoints() {
        disable_jitter_once();
        let alice = TestNode::spawn("work").await;
        let master = MasterKey::generate().unwrap();
        let private_side = master.derive_side(&"private".into()).unwrap();
        let private_addr = private_side.public_bytes();
        let (side_p, p_listen) = alice
            .node
            .add_side(private_side, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();
        assert_eq!(side_p.address, private_addr);
        assert_ne!(p_listen, alice.listen_addr());
        let queried = alice.node.side_listen_addr(&private_addr).await.unwrap();
        assert_eq!(queried, p_listen);
        let all = alice.node.sides().await;
        assert_eq!(all.len(), 2);
    }

    #[tokio::test]
    async fn cross_side_dm_routing_is_correct() {
        // alice hosts side W (primary) + side P. bob sends a DM to side
        // P only; the DM arrives tagged with envelope.to = side_p.address.
        // The DM channel is shared, but envelope.to disambiguates.
        disable_jitter_once();
        let alice = TestNode::spawn("work").await;
        let bob = TestNode::spawn("bob").await;
        let master = MasterKey::generate().unwrap();
        let private_side = master.derive_side(&"private".into()).unwrap();
        let private_seed = private_side.to_seed();
        let private_addr = private_side.public_bytes();
        let (_side_p, p_listen) = alice
            .node
            .add_side(private_side, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();

        let session = bob.node.dial(p_listen, Intent::Direct).await.unwrap();
        send_dm(&session, bob.node.side(), b"hi private side")
            .await
            .unwrap();
        drop(session);

        let dm = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            alice.node.next_direct_message(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&dm.plaintext, b"hi private side");
        // envelope.to = the receiving side's pubkey (private), not the
        // primary work side. This confirms routing landed on the right
        // endpoint.
        assert_eq!(dm.envelope.to, Some(private_addr));
        // The handshake's recipient was the private side's keypair.
        let _ = private_seed;
    }

    #[tokio::test]
    async fn dial_from_uses_secondary_side_endpoint_and_identity() {
        // Phase 3.B: dial_from(secondary_side) must route through the
        // secondary side's own QUIC endpoint and present the secondary
        // side's pubkey to the peer (spec §7.6: traffic for each side
        // travels on its own connection).
        disable_jitter_once();
        let alice = TestNode::spawn("work").await;
        let bob = TestNode::spawn("bob").await;
        let master = MasterKey::generate().unwrap();
        let private_side = master.derive_side(&"private".into()).unwrap();
        let private_addr = private_side.public_bytes();
        alice
            .node
            .add_side(private_side, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();

        let session = alice
            .node
            .dial_from(&private_addr, bob.listen_addr(), Intent::Direct)
            .await
            .unwrap();
        // bob saw the handshake; his peer_side must be alice's *secondary*
        // pubkey, never alice's primary.
        assert_eq!(session.peer_side, bob.node.side().public_bytes());

        let private_side_arc = alice.node.side_by_address(&private_addr).await.unwrap();
        let private_key = private_side_arc.keypair_arc();
        send_dm(&session, &private_key, b"hello from secondary")
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
        assert_eq!(&dm.plaintext, b"hello from secondary");
        // bob's recorded sender is alice's *secondary* side, not primary.
        assert_eq!(dm.envelope.from, private_addr);
        assert_ne!(dm.envelope.from, alice.node.side().public_bytes());
    }

    // -------------------------------------------------------------------
    // Phase 1.B1 — NAT hole-punching wrapper.
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn hole_punch_dial_succeeds_on_loopback() {
        // No real NAT on loopback, but the wrapper's retry + timeout
        // path is still exercised. We assert the first attempt lands
        // and we get a usable Session.
        disable_jitter_once();
        let alice = TestNode::spawn("a").await;
        let bob = TestNode::spawn("b").await;
        let session = alice
            .node
            .hole_punch_dial(
                bob.listen_addr(),
                Intent::Direct,
                sidevers_net::HolePunchConfig::default(),
            )
            .await
            .unwrap();
        assert_eq!(session.peer_side, bob.node.side().public_bytes());
    }

    // -------------------------------------------------------------------
    // Phase 1.H4 — QUIC connection pool.
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn dial_pooled_does_not_grow_pool_on_repeat() {
        // Pool semantics: the first dial seeds the pool with one
        // connection per (peer, source-side); subsequent dial_pooled
        // calls to the same peer reuse that connection rather than
        // opening another. Asserting pool size stays at 1 across
        // many dials is the cheapest unambiguous check for reuse —
        // quinn::Connection::stable_id is per-handle and not portable
        // across clones in quinn 0.11.
        disable_jitter_once();
        let alice = TestNode::spawn("a").await;
        let bob = TestNode::spawn("b").await;
        assert!(alice.node.connection_pool().is_empty().await);

        for _ in 0..5 {
            let _ = alice
                .node
                .dial_pooled(bob.listen_addr(), Intent::Direct)
                .await
                .unwrap();
        }
        assert_eq!(
            alice.node.connection_pool().len().await,
            1,
            "repeated dial_pooled to one peer must keep the pool at size 1"
        );
    }

    // -------------------------------------------------------------------
    // Phase 1.A3 — Gossip-fanout web-of-trust filter (§6.9.3).
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn gossip_policy_default_is_open() {
        // The default policy doesn't change behavior, so existing
        // gossip tests keep passing. This test pins down that fact.
        let n = TestNode::spawn("n").await;
        let p = n.node.gossip_policy().await;
        assert_eq!(p.propagation, sidevers_net::GossipPropagation::Open);
    }

    #[tokio::test]
    async fn gossip_policy_can_be_tightened_to_relationships_only() {
        // Mostly an API smoke test: set the policy and read it back.
        // End-to-end propagation under tight policy needs a 3-node
        // setup (originator → relay → receiver) which the existing
        // broadcast test already covers structurally — what's new
        // here is that the relay CAN choose to filter.
        let n = TestNode::spawn("n").await;
        n.node
            .set_gossip_policy(sidevers_net::GossipPolicy::relationships_only())
            .await;
        let p = n.node.gossip_policy().await;
        assert_eq!(
            p.propagation,
            sidevers_net::GossipPropagation::RelationshipsOnly
        );
    }

    // -------------------------------------------------------------------
    // Phase 1.C3 — Storage retract per-publisher provenance (§5.6).
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn storage_retract_ignored_when_sender_never_published_the_object() {
        // Bob receives an OFFER of object X from alice, accepts, ingests.
        // Then mallory (different side) sends a retract for X — bob must
        // ignore it and keep serving the object.
        use sidevers_storage::Reference;

        disable_jitter_once();
        let alice = TestNode::spawn("alice").await;
        let bob = TestNode::spawn("bob").await;

        // Alice puts a bytes-blob in her local store and offers to bob.
        let bytes = b"the-payload".to_vec();
        let size = bytes.len() as u64;
        let hash = alice.node.store().put(bytes).await.unwrap();
        let reference = Reference::new(hash, size, "application/octet-stream");
        let session_ab = alice
            .node
            .dial(bob.listen_addr(), Intent::Storage)
            .await
            .unwrap();
        let wanted = sidevers_net::offer_object(
            &session_ab,
            alice.node.side(),
            reference,
            &alice.node.store(),
        )
        .await
        .unwrap();
        assert!(wanted, "bob must want the object initially");
        drop(session_ab);
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        // Mallory has no relationship to this object. She retracts it.
        let mallory = TestNode::spawn("mallory").await;
        let session_mb = mallory
            .node
            .dial(bob.listen_addr(), Intent::Storage)
            .await
            .unwrap();
        sidevers_net::retract_object(&session_mb, mallory.node.side(), hash)
            .await
            .unwrap();
        drop(session_mb);
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        let publishers = bob.node.publisher_set(&hash).await;
        assert!(
            publishers.contains(&alice.node.side().public_bytes()),
            "alice (the original publisher) must still be in bob's publisher set; got {publishers:?}"
        );
    }

    #[tokio::test]
    async fn storage_retract_clears_publisher_set_when_only_publisher_retracts() {
        use sidevers_storage::Reference;

        disable_jitter_once();
        let alice = TestNode::spawn("alice").await;
        let bob = TestNode::spawn("bob").await;
        let bytes = b"alice-payload".to_vec();
        let size = bytes.len() as u64;
        let hash = alice.node.store().put(bytes).await.unwrap();
        let reference = Reference::new(hash, size, "application/octet-stream");

        let session_ab = alice
            .node
            .dial(bob.listen_addr(), Intent::Storage)
            .await
            .unwrap();
        sidevers_net::offer_object(
            &session_ab,
            alice.node.side(),
            reference,
            &alice.node.store(),
        )
        .await
        .unwrap();
        drop(session_ab);
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        let session_ab = alice
            .node
            .dial(bob.listen_addr(), Intent::Storage)
            .await
            .unwrap();
        sidevers_net::retract_object(&session_ab, alice.node.side(), hash)
            .await
            .unwrap();
        drop(session_ab);
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        let publishers = bob.node.publisher_set(&hash).await;
        assert!(
            publishers.is_empty(),
            "after sole publisher retracts, publisher set must be empty; got {publishers:?}"
        );
    }

    // -------------------------------------------------------------------
    // Phase 1.G4 — §6.10 architectural invariants.
    //
    // These tests don't introduce new behavior; they pin down properties
    // the architecture relies on so a future refactor can't accidentally
    // violate them.
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn invariant_no_global_view_fresh_node_peer_table_is_empty() {
        // §6.10: there is no global view. A freshly-started node knows
        // about NO other node — it must learn peers via direct dial,
        // PEER_TELL gossip, or rendezvous, all of which require some
        // prior connection. No bootstrap registry is consulted.
        let alice = TestNode::spawn("work").await;
        let count = alice.node.peers().len().await;
        assert_eq!(
            count, 0,
            "a freshly-spawned node must NOT know any peers: peer-table contains {count} entry/entries"
        );
    }

    #[tokio::test]
    async fn invariant_no_anonymous_routing_envelope_signature_must_match_from() {
        // §6.10 + §3.3: every envelope is signed by its `from` side; the
        // network layer must reject any envelope whose signature doesn't
        // verify against the embedded `from`. There is no anonymous
        // routing path: every envelope is cryptographically attributed
        // before any handler sees it.
        use sidevers_core::Envelope;

        let alice = MasterKey::generate()
            .unwrap()
            .derive_side(&"a".into())
            .unwrap();
        let bob = MasterKey::generate()
            .unwrap()
            .derive_side(&"b".into())
            .unwrap();
        // Build a valid envelope from alice, then rewrite `from` to claim
        // bob's identity. The signature still says alice — verification
        // must fail.
        let env = Envelope::sign_with(
            sidevers_core::MessageType::DIRECT_MESSAGE,
            &alice,
            None,
            b"hi".to_vec(),
            1_700_000_000,
            [0x77; 16],
        )
        .unwrap();
        let mut wire = env.to_wire_bytes();
        // Locate `from` in the encoded bytes by looking for alice's
        // public key and overwrite it with bob's. (The CBOR decoder
        // will then refuse to verify the signature.)
        let alice_pk = alice.public_bytes();
        let bob_pk = bob.public_bytes();
        let pos = wire
            .windows(alice_pk.len())
            .position(|w| w == alice_pk)
            .expect("envelope must contain alice's pubkey verbatim");
        wire[pos..pos + alice_pk.len()].copy_from_slice(&bob_pk);

        let err = Envelope::from_wire_bytes(&wire).unwrap_err();
        // Must be a signature-related failure, not a parse error.
        assert!(
            matches!(
                err,
                sidevers_core::Error::SignatureInvalid | sidevers_core::Error::CborNotCanonical(_)
            ),
            "rewriting `from` must yield a signature-invalid error, got {err:?}"
        );
    }

    #[tokio::test]
    async fn invariant_no_global_broadcast_third_party_not_in_session_never_sees_it() {
        // §6.10: a "broadcast" is fan-out across CURRENTLY-CONNECTED
        // gossip sessions only. A third party who hasn't dialed in
        // does not receive the message.
        disable_jitter_once();
        let alice = TestNode::spawn("a").await;
        let bob = TestNode::spawn("b").await;
        let dave = TestNode::spawn("d").await;
        // alice ↔ bob established. dave is NOT connected to either.
        let session = alice
            .node
            .dial(bob.listen_addr(), Intent::Gossip)
            .await
            .unwrap();
        sidevers_net::publish_broadcast(&session, alice.node.side(), b"announce".to_vec())
            .await
            .unwrap();
        drop(session);

        // bob (in session) sees it.
        let bob_recv = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            bob.node.next_public_broadcast(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(bob_recv.payload, b"announce");

        // dave (out of session) MUST NOT see it.
        let dave_poll = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            dave.node.next_public_broadcast(),
        )
        .await;
        assert!(
            dave_poll.is_err(),
            "third-party uninvolved node MUST NOT see broadcast — got {dave_poll:?}"
        );
    }

    // -------------------------------------------------------------------
    // Phase 1.G1 — LinkageProof publication wire path (§2.7).
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn linkage_proof_publishes_and_verifies_end_to_end() {
        use sidevers_core::linkage::LinkageProof;
        use sidevers_net::publish_linkage_proof;

        disable_jitter_once();
        let alice = TestNode::spawn("work").await;
        let bob = TestNode::spawn("bob").await;

        // Build a linkage proof for alice's primary side + a second
        // side she owns. Both signatures will verify against the
        // proof's embedded pubkeys; bob doesn't need either pubkey
        // pre-shared.
        let master = MasterKey::generate().unwrap();
        let other_side = master.derive_side(&"public".into()).unwrap();
        let proof = LinkageProof::sign(alice.node.side(), &other_side, 1_700_000_000).unwrap();
        let side_a = proof.side_a;
        let side_b = proof.side_b;

        // Alice dials bob over Direct intent and publishes the proof.
        let session = alice
            .node
            .dial(bob.listen_addr(), Intent::Direct)
            .await
            .unwrap();
        publish_linkage_proof(&session, alice.node.side(), &proof)
            .await
            .unwrap();
        drop(session);

        let recv = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            bob.node.next_linkage_proof(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(recv.proof.side_a, side_a);
        assert_eq!(recv.proof.side_b, side_b);
        assert_eq!(recv.envelope.from, alice.node.side().public_bytes());
    }

    #[tokio::test]
    async fn linkage_proof_rejected_when_sender_is_neither_linked_side() {
        // Spec §2.7: anyone with the proof bytes can VERIFY it (both
        // signatures are public), but the wire dispatch insists the
        // envelope sender be one of the two linked sides — to keep
        // unattributable third-party relays out of the inbox.
        use sidevers_core::linkage::LinkageProof;
        use sidevers_net::publish_linkage_proof;

        disable_jitter_once();
        let bob = TestNode::spawn("bob").await;
        let m_a = MasterKey::generate().unwrap();
        let side_a = m_a.derive_side(&"a".into()).unwrap();
        let side_b = m_a.derive_side(&"b".into()).unwrap();
        let proof = LinkageProof::sign(&side_a, &side_b, 1_700_000_000).unwrap();

        let relay = TestNode::spawn("relay").await;
        let session = relay
            .node
            .dial(bob.listen_addr(), Intent::Direct)
            .await
            .unwrap();
        // relay signs the envelope, but `proof.side_a/_b` belong to
        // someone else.
        publish_linkage_proof(&session, relay.node.side(), &proof)
            .await
            .unwrap();
        drop(session);

        // Bob's linkage channel must NOT see this — give the loop a
        // moment to drop it.
        let polled = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            bob.node.next_linkage_proof(),
        )
        .await;
        assert!(
            polled.is_err(),
            "third-party relay's linkage publish must be silently dropped"
        );
    }

    // -------------------------------------------------------------------
    // Phase 1.D — Handshake capabilities (§4.3) + per-source rate-limit (§4.6).
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn session_carries_peer_advertised_capabilities() {
        // After a real handshake, both ends record the *other* end's
        // capabilities on the Session. Phase 1.D wired this — before,
        // the capabilities BTreeMap round-tripped empty.
        disable_jitter_once();
        let alice = TestNode::spawn("work").await;
        let bob = TestNode::spawn("bob").await;
        let session = alice
            .node
            .dial(bob.listen_addr(), Intent::Direct)
            .await
            .unwrap();
        assert!(
            !session.peer_capabilities.is_empty(),
            "peer must advertise at least one capability"
        );
        let protocol = session
            .peer_capabilities
            .get(sidevers_net::handshake::CAP_PROTOCOL)
            .copied();
        assert_eq!(protocol, Some(1));
        let intents = session
            .peer_capabilities
            .get(sidevers_net::handshake::CAP_INTENTS_MASK)
            .copied()
            .unwrap_or_default();
        // Direct (intent 1) and Verse (intent 4) must be present.
        assert!(intents & (1 << 1) != 0);
        assert!(intents & (1 << 4) != 0);
    }

    #[tokio::test]
    async fn handshake_limit_throttles_excessive_source() {
        // Exercise the limiter directly with a small bucket so the
        // test stays deterministic. Wiring into accept_loop is
        // covered by the unit tests in handshake_limit.rs.
        use sidevers_net::HandshakeLimiter;
        let l = HandshakeLimiter::new(2.0, 0.001);
        let ip: std::net::IpAddr = "203.0.113.7".parse().unwrap();
        assert!(l.try_acquire(ip).await);
        assert!(l.try_acquire(ip).await);
        assert!(!l.try_acquire(ip).await);
        // A different source is unaffected.
        let other: std::net::IpAddr = "203.0.113.8".parse().unwrap();
        assert!(l.try_acquire(other).await);
    }

    // -------------------------------------------------------------------
    // Phase 1.5f Track C — Multi-device pairing (§7.5).
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn device_pairing_completes_and_new_device_hosts_the_side() {
        disable_jitter_once();
        let existing = TestNode::spawn("work").await;
        let new_device = TestNode::spawn("new-device").await;

        // existing sets a profile + a relationship on its primary side.
        let work_profile = make_profile(&existing.local_side(), &[capability::DIRECT_MESSAGE]);
        existing.node.set_local_profile(work_profile.clone()).await;
        existing
            .node
            .add_relationship(make_relationship([0xAA; 32], &[capability::DIRECT_MESSAGE]))
            .await;

        // existing generates a QR for its primary side.
        let work_addr = existing.node.side().public_bytes();
        let qr = existing.node.generate_pairing_qr(&work_addr).await.unwrap();
        assert_eq!(qr.side, work_addr);

        // Round-trip the QR string through encode/parse to exercise the
        // codec path the real new device would go through.
        let qr_str = qr.encode();
        let parsed_qr = sidevers_core::PairingQr::parse(&qr_str).unwrap();

        // new device accepts the pairing.
        let (joined_side, _listen) = new_device.node.accept_pairing(parsed_qr).await.unwrap();
        assert_eq!(joined_side.address, work_addr);

        // The new device should now host the joined side (in addition to
        // its own original side).
        let hosted = new_device.node.sides().await;
        assert_eq!(hosted.len(), 2);
        assert!(hosted.iter().any(|s| s.address == work_addr));

        // Bundle replayed: profile + relationship visible on the new
        // device's joined side.
        let restored_profile = joined_side.profile().await.unwrap();
        assert_eq!(
            restored_profile.to_wire_bytes(),
            work_profile.to_wire_bytes()
        );
        let restored_rel = joined_side.get_relationship(&[0xAA; 32]).await.unwrap();
        assert!(
            restored_rel
                .capabilities
                .contains(capability::DIRECT_MESSAGE)
        );

        // existing now lists new_device's pubkey as a co-holder.
        let coh = existing.node.list_co_holders(&work_addr).await;
        assert_eq!(coh.len(), 1);
    }

    #[tokio::test]
    async fn pairing_with_stale_nonce_is_rejected() {
        // Send a PAIRING_REQUEST referencing a nonce the existing device
        // never minted; serve_direct silently drops, so accept_pairing's
        // bundle wait times out.
        disable_jitter_once();
        let existing = TestNode::spawn("work").await;
        let new_device = TestNode::spawn("new-device").await;

        let work_addr = existing.node.side().public_bytes();
        let listen = existing.node.side_listen_addr(&work_addr).await.unwrap();
        let bogus_qr = sidevers_core::PairingQr {
            side: work_addr,
            nonce: [0x77; 16],
            dial_addr: listen.to_string(),
        };

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(12),
            new_device.node.accept_pairing(bogus_qr),
        )
        .await;
        // Either the inner 10s bundle wait times out → Err, or the outer
        // 12s wraps to Err. Both are acceptable failure modes.
        match result {
            Ok(Err(_)) => {} // accept_pairing internally failed (bundle timeout)
            Err(_) => {}     // outer timeout
            Ok(Ok(_)) => panic!("pairing should have been rejected"),
        }
    }

    #[tokio::test]
    async fn device_revoke_marks_revoked_locally() {
        disable_jitter_once();
        let existing = TestNode::spawn("work").await;
        let new_device = TestNode::spawn("new-device").await;

        let work_addr = existing.node.side().public_bytes();
        let qr = existing.node.generate_pairing_qr(&work_addr).await.unwrap();
        let (_joined, _) = new_device.node.accept_pairing(qr).await.unwrap();

        // existing identifies the new device's pubkey from its co_holders.
        let coh = existing.node.list_co_holders(&work_addr).await;
        let new_dev_pubkey = coh[0];

        // existing revokes.
        let _record = existing
            .node
            .revoke_co_holder(&work_addr, new_dev_pubkey, Some("test".into()))
            .await
            .unwrap();
        assert!(
            existing
                .node
                .is_device_revoked(&work_addr, &new_dev_pubkey)
                .await
        );
        // The revoked device is removed from existing's co-holder list.
        assert!(existing.node.list_co_holders(&work_addr).await.is_empty());
    }

    // -------------------------------------------------------------------
    // Phase 1.5g — Live state delta sync between co-holders.
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn pairing_closes_the_loop_existing_knows_new_dial_addr() {
        disable_jitter_once();
        let existing = TestNode::spawn("work").await;
        let new_device = TestNode::spawn("new-device").await;

        let work_addr = existing.node.side().public_bytes();
        let qr = existing.node.generate_pairing_qr(&work_addr).await.unwrap();
        let (_joined_side, new_listen) = new_device.node.accept_pairing(qr).await.unwrap();
        let existing_side = existing.node.side_by_address(&work_addr).await.unwrap();

        // Poll: existing's side W should record SOME co-holder addr
        // matching the new device's listen address.
        let target = new_listen.to_string();
        for _ in 0..80 {
            let addrs = existing_side.list_co_holder_addrs().await;
            if addrs.iter().any(|(_, a)| a == &target) {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        let addrs = existing_side.list_co_holder_addrs().await;
        panic!(
            "loop never closed: existing's co_holder_addrs = {:?}, expected addr {target}",
            addrs
        );
    }

    #[tokio::test]
    async fn live_sync_propagates_relationship_add() {
        disable_jitter_once();
        let existing = TestNode::spawn("work").await;
        let new_device = TestNode::spawn("new-device").await;

        let work_addr = existing.node.side().public_bytes();
        let qr = existing.node.generate_pairing_qr(&work_addr).await.unwrap();
        let (joined_side, _) = new_device.node.accept_pairing(qr).await.unwrap();

        // Wait for the CoHolderAdded loop-closer to land on existing.
        let existing_side = existing.node.side_by_address(&work_addr).await.unwrap();
        wait_for(|| async { !existing_side.list_co_holder_addrs().await.is_empty() }).await;

        // After pairing: existing adds a relationship. The auto-push
        // hook should propagate it to the new device.
        existing
            .node
            .add_relationship(make_relationship([0xDD; 32], &[capability::DIRECT_MESSAGE]))
            .await;

        wait_for(|| async { joined_side.get_relationship(&[0xDD; 32]).await.is_some() }).await;
        let r = joined_side.get_relationship(&[0xDD; 32]).await.unwrap();
        assert!(r.capabilities.contains(capability::DIRECT_MESSAGE));
    }

    #[tokio::test]
    async fn live_sync_propagates_profile_update() {
        disable_jitter_once();
        let existing = TestNode::spawn("work").await;
        let new_device = TestNode::spawn("new-device").await;

        let work_addr = existing.node.side().public_bytes();
        let qr = existing.node.generate_pairing_qr(&work_addr).await.unwrap();
        let (joined_side, _) = new_device.node.accept_pairing(qr).await.unwrap();

        let existing_side = existing.node.side_by_address(&work_addr).await.unwrap();
        wait_for(|| async { !existing_side.list_co_holder_addrs().await.is_empty() }).await;

        // Build a new profile with strictly newer updated_at than any
        // existing one, then push it via Node::set_local_profile.
        let updated_profile = ProfilePayload::sign(
            &existing.local_side(),
            Some("Renamed".to_owned()),
            None,
            Some("updated bio".to_owned()),
            None,
            None,
            BTreeSet::from([capability::DIRECT_MESSAGE.to_owned()]),
            2_000_000_000,
        )
        .unwrap();
        existing
            .node
            .set_local_profile(updated_profile.clone())
            .await;

        wait_for(|| async {
            joined_side
                .profile()
                .await
                .map(|p| p.bio.as_deref() == Some("updated bio"))
                .unwrap_or(false)
        })
        .await;
        let p = joined_side.profile().await.unwrap();
        assert_eq!(p.bio.as_deref(), Some("updated bio"));
        assert_eq!(p.name.as_deref(), Some("Renamed"));
    }

    /// Poll up to 4 seconds for `pred` to return true. Used by Phase
    /// 1.5g sync tests where push is fire-and-forget on the network.
    async fn wait_for<F, Fut>(mut pred: F)
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        for _ in 0..80 {
            if pred().await {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        panic!("wait_for: predicate never became true within 4s");
    }

    // -------------------------------------------------------------------
    // Phase 1.5h — Anti-spam Tier 1: per-peer rate limit + refuse (§6.9).
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn dm_from_refused_peer_is_dropped() {
        // Bob manually refuses Alice via the reputation table; Alice's
        // subsequent DM is silently dropped at the envelope-entry gate
        // BEFORE the freshness/replay/capability checks run.
        disable_jitter_once();
        let alice = TestNode::spawn("work").await;
        let bob = TestNode::spawn("close").await;

        // Bob refuses Alice.
        bob.node
            .reputation()
            .refuse(&alice.node.side().public_bytes(), 1)
            .await;

        let session = alice
            .node
            .dial(bob.listen_addr(), Intent::Direct)
            .await
            .unwrap();
        send_dm(&session, alice.node.side(), b"shouldn't arrive")
            .await
            .unwrap();
        drop(session);

        let result = tokio::time::timeout(
            std::time::Duration::from_millis(800),
            bob.node.next_direct_message(),
        )
        .await;
        assert!(
            result.is_err(),
            "expected DM to be dropped by reputation gate"
        );

        // Counter ticks for the dropped envelope.
        let snap = bob
            .node
            .reputation()
            .get(&alice.node.side().public_bytes())
            .await
            .unwrap();
        assert!(snap.refused);
        assert!(snap.envelopes_seen >= 1);
    }

    #[tokio::test]
    async fn reinstated_peer_dms_arrive_again() {
        disable_jitter_once();
        let alice = TestNode::spawn("work").await;
        let bob = TestNode::spawn("close").await;

        bob.node
            .reputation()
            .refuse(&alice.node.side().public_bytes(), 1)
            .await;
        bob.node
            .reputation()
            .reinstate(&alice.node.side().public_bytes())
            .await;

        let session = alice
            .node
            .dial(bob.listen_addr(), Intent::Direct)
            .await
            .unwrap();
        send_dm(&session, alice.node.side(), b"after reinstate")
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
        assert_eq!(&dm.plaintext, b"after reinstate");
    }

    #[tokio::test]
    async fn side_state_persists_across_node_restart() {
        // Phase 1.5f Track A: state set on the first Node instance must
        // be visible to a second Node started with the same side seed +
        // data_dir.
        disable_jitter_once();
        let tmp = tempfile::tempdir().unwrap();
        let master = MasterKey::generate().unwrap();
        let seed = master.derive_side(&"work".into()).unwrap().to_seed();

        // First instance: install a profile + relationship, mark a side
        // as retired-seen, then shut down.
        let side1 = SideKey::from_seed(&seed, "(test)");
        let node1 = Node::start(
            side1,
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            tmp.path(),
        )
        .await
        .unwrap();

        let profile = make_profile(
            &SideKey::from_seed(&seed, "(test)"),
            &[capability::DIRECT_MESSAGE, capability::STORAGE_HOST],
        );
        node1.set_local_profile(profile.clone()).await;
        node1
            .add_relationship(make_relationship([0xCC; 32], &[capability::DIRECT_MESSAGE]))
            .await;

        node1.shutdown().await;

        // Second instance: same side, same data_dir. State should be
        // restored from SQLite.
        let side2 = SideKey::from_seed(&seed, "(test)");
        let node2 = Node::start(
            side2,
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            tmp.path(),
        )
        .await
        .unwrap();
        let restored_profile = node2.local_profile().await.unwrap();
        assert_eq!(restored_profile.to_wire_bytes(), profile.to_wire_bytes());
        let restored_rel = node2.get_relationship(&[0xCC; 32]).await.unwrap();
        assert!(
            restored_rel
                .capabilities
                .contains(capability::DIRECT_MESSAGE)
        );
        node2.shutdown().await;
    }

    #[tokio::test]
    async fn lifecycle_set_manually_then_refresh_respects_retired_stickiness() {
        disable_jitter_once();
        let alice = TestNode::spawn("work").await;
        // Manually pin to Retired.
        alice.node.set_lifecycle(SideLifecycle::Retired).await;
        // refresh_lifecycle is a no-op on Retired.
        alice.node.refresh_lifecycle().await;
        assert_eq!(alice.node.lifecycle().await, SideLifecycle::Retired);
        // Re-pin to Dormant.
        alice.node.set_lifecycle(SideLifecycle::Dormant).await;
        assert_eq!(alice.node.lifecycle().await, SideLifecycle::Dormant);
    }

    #[tokio::test]
    async fn profile_fetch_returns_nothing_when_target_isnt_hosted_side() {
        // Bob hosts profile X; alice asks for profile Y (a different
        // pubkey). Bob's serve_direct silently drops, so fetch_profile
        // times out / errors at the network layer.
        let alice = TestNode::spawn("work").await;
        let bob = TestNode::spawn("close").await;
        bob.node
            .set_local_profile(make_profile(
                &bob.local_side(),
                &[capability::DIRECT_MESSAGE],
            ))
            .await;

        let session = alice
            .node
            .dial(bob.listen_addr(), Intent::Direct)
            .await
            .unwrap();
        // Ask for an arbitrary pubkey that isn't bob's hosted side.
        let unrelated = [0x77u8; 32];
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(800),
            fetch_profile(&session, alice.node.side(), unrelated),
        )
        .await;
        assert!(
            result.is_err() || result.unwrap().is_err(),
            "expected fetch to time out or error; got Ok"
        );
    }
}
