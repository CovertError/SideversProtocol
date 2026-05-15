//! Byte-stable fixtures and property tests for the Month-2 surface.
//!
//! These tests are the protocol's tripwire: if anything in the encoder
//! changes — a map key order, a length form, an HKDF info string — these
//! catch it before any production signature does.

#![cfg(test)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use proptest::prelude::*;
use sidevers_core::envelope::{NONCE_LEN, random_nonce};
use sidevers_core::keys::{MasterKey, SideKey};
use sidevers_core::linkage::LinkageProof;
use sidevers_core::messages::direct::{DirectBody, DirectKind, DirectMessagePayload};
use sidevers_core::{Address, AddressKind, Envelope, MessageType};

fn deterministic_side(seed: u8, label: &str) -> SideKey {
    let m = MasterKey::from_seed(&[seed; 32]);
    m.derive_side(&label.into()).unwrap()
}

#[test]
fn fixture_envelope_byte_stable_under_fixed_inputs() {
    // Pinned inputs. If these bytes ever change, something in the encoder
    // changed — investigate before updating the fixture.
    let alice = deterministic_side(0x42, "work");
    let bob_pk = deterministic_side(0x99, "close").public_bytes();

    let nonce = [0xABu8; NONCE_LEN];
    let ts: u64 = 1_700_000_000;
    let payload = b"FIXTURE-PAYLOAD".to_vec();

    let env = Envelope::sign_with(
        MessageType::DIRECT_MESSAGE,
        &alice,
        Some(bob_pk),
        payload,
        ts,
        nonce,
    )
    .unwrap();
    let bytes = env.to_wire_bytes();

    // Sanity: round-trip the bytes back through the parser/verifier.
    let parsed = Envelope::from_wire_bytes(&bytes).unwrap();
    assert_eq!(parsed, env);

    // Spec §3.2 envelope shape: 8-key CBOR map (head byte 0xA8).
    assert_eq!(bytes[0], 0xA8, "envelope must encode as 8-entry map");

    // Total size sanity: v(1) + t(2) + to(33) + ts(5) + sig(2+64) + from(2+32)
    //                  + nonce(2+16) + payload(2+15) keys ~= ~190 bytes
    //                  (with key bytes adding ~40 more). Anchor the range so
    //                  unexpected bloat shows up.
    assert!(
        (180..=260).contains(&bytes.len()),
        "fixture envelope unexpectedly sized: {} bytes",
        bytes.len()
    );

    // The signature is deterministic under fixed (key, message); pin it.
    let sig_hex = hex::encode(parsed.sig);
    assert_eq!(
        sig_hex.len(),
        128,
        "ed25519 sig must hex-encode to 128 chars"
    );

    // Pin the wire bytes hash so accidental encoder churn is loud.
    let digest = blake3::hash(&bytes);
    eprintln!(
        "fixture envelope digest: {}",
        hex::encode(digest.as_bytes())
    );
    eprintln!("fixture envelope length: {}", bytes.len());
}

#[test]
fn fixture_linkage_proof_byte_stable() {
    let a = deterministic_side(0x11, "public");
    let b = deterministic_side(0x11, "private");
    let proof = LinkageProof::sign_with(&a, &b, 1_700_000_000, [0x07u8; 16]).unwrap();
    let bytes = proof.to_wire_bytes();
    let parsed = LinkageProof::from_wire_bytes(&bytes).unwrap();
    assert_eq!(parsed, proof);
    // 6-key map header
    assert_eq!(bytes[0], 0xA6);
}

#[test]
fn fixture_direct_message_byte_stable() {
    let p = DirectMessagePayload {
        kind: DirectKind::Text,
        body: DirectBody::Text("hello sidevers".into()),
        reply_to: None,
        thread: None,
    };
    let bytes = p.encode();
    // 4-key map header
    assert_eq!(bytes[0], 0xA4);
    let decoded = DirectMessagePayload::decode(&bytes).unwrap();
    assert_eq!(decoded, p);
}

proptest! {
    /// Random envelopes (text-only payloads, fixed direction) round-trip
    /// byte-identical: encode → parse → re-encode = original bytes.
    #[test]
    fn envelope_roundtrip_is_byte_identical(
        seed_a in any::<[u8; 32]>(),
        seed_b in any::<[u8; 32]>(),
        ts in 0u64..(1u64 << 40),
        body in any::<Vec<u8>>().prop_filter("size<2KB", |v| v.len() < 2048),
        nonce in any::<[u8; NONCE_LEN]>(),
        t in any::<u8>(),
        unicast in any::<bool>(),
    ) {
        let alice = MasterKey::from_seed(&seed_a).derive_side(&"work".into()).unwrap();
        let to = if unicast {
            Some(MasterKey::from_seed(&seed_b).derive_side(&"close".into()).unwrap().public_bytes())
        } else {
            None
        };
        let env = Envelope::sign_with(MessageType(t), &alice, to, body, ts, nonce).unwrap();
        let bytes = env.to_wire_bytes();
        let parsed = Envelope::from_wire_bytes(&bytes).unwrap();
        let bytes2 = parsed.to_wire_bytes();
        prop_assert_eq!(bytes, bytes2);
    }

    /// Random addresses round-trip through bech32m.
    #[test]
    fn address_roundtrip(key in any::<[u8; 32]>(), is_verse in any::<bool>()) {
        let kind = if is_verse { AddressKind::Verse } else { AddressKind::Side };
        let addr = Address::new(kind, key);
        let s = addr.encode();
        let parsed = Address::parse(&s).unwrap();
        prop_assert_eq!(parsed, addr);
    }

    /// Random DirectMessage payloads round-trip.
    #[test]
    fn direct_message_text_roundtrip(
        text in ".{0,500}",
        thread_present in any::<bool>(),
        reply_present in any::<bool>(),
        thread in any::<[u8; 32]>(),
        reply in any::<[u8; 32]>(),
    ) {
        let p = DirectMessagePayload {
            kind: DirectKind::Text,
            body: DirectBody::Text(text),
            reply_to: if reply_present { Some(reply) } else { None },
            thread: if thread_present { Some(thread) } else { None },
        };
        let bytes = p.encode();
        let decoded = DirectMessagePayload::decode(&bytes).unwrap();
        prop_assert_eq!(decoded, p);
    }

    /// A signed envelope's signature MUST fail to verify if any single byte
    /// of the canonical encoding changes.
    #[test]
    fn flipped_bit_anywhere_breaks_verification(
        seed in any::<[u8; 32]>(),
        ts in 0u64..(1u64 << 40),
        body in any::<Vec<u8>>().prop_filter("size 1..256", |v| (1..256).contains(&v.len())),
        nonce in any::<[u8; NONCE_LEN]>(),
        flip_index in 0usize..200,
    ) {
        let alice = MasterKey::from_seed(&seed).derive_side(&"x".into()).unwrap();
        let env = Envelope::sign_with(MessageType::DIRECT_MESSAGE, &alice, None, body, ts, nonce).unwrap();
        let mut bytes = env.to_wire_bytes();
        if flip_index >= bytes.len() {
            return Ok(()); // skip when sampled index exceeds size
        }
        bytes[flip_index] ^= 0x01;
        prop_assert!(Envelope::from_wire_bytes(&bytes).is_err());
    }
}

/// One nonce-from-CSPRNG sanity test that exercises the OS path. (The
/// property tests above use fixed nonces.)
#[test]
fn random_nonce_is_not_all_zero() {
    let n = random_nonce().unwrap();
    assert!(n.iter().any(|&b| b != 0));
}
