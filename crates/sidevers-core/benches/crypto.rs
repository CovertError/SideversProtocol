//! Phase 1.F1: criterion baselines for the hot crypto paths.
//!
//! Track regressions in the Ed25519 sign/verify, X25519 ECDH, and the
//! payload seal/open AEAD path. These are the per-envelope-cost
//! operations — anything that makes them slower shows up here.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use criterion::{Criterion, criterion_group, criterion_main};
use sidevers_core::envelope::random_nonce;
use sidevers_core::keys::{MasterKey, SideKey};
use sidevers_core::payload;

fn fixture_side(seed: u8) -> SideKey {
    let m = MasterKey::from_seed(&[seed; 32]);
    m.derive_side(&"bench".into()).unwrap()
}

fn bench_sign(c: &mut Criterion) {
    let alice = fixture_side(0x01);
    let msg = b"a-fixed-32-byte-message---------";
    c.bench_function("ed25519_sign_32b", |b| {
        b.iter(|| {
            let _sig = alice.sign(std::hint::black_box(msg));
        });
    });
}

fn bench_verify(c: &mut Criterion) {
    let alice = fixture_side(0x02);
    let msg = b"a-fixed-32-byte-message---------";
    let sig = alice.sign(msg);
    let pk = sidevers_core::keys::PublicKey::from_bytes(&alice.public_bytes()).unwrap();
    c.bench_function("ed25519_verify_32b", |b| {
        b.iter(|| {
            // Verification is the cost we pay per inbound envelope.
            let _ = pk.verify(std::hint::black_box(msg), std::hint::black_box(&sig));
        });
    });
}

fn bench_seal(c: &mut Criterion) {
    let alice = fixture_side(0x03);
    let bob = fixture_side(0x04);
    let bob_pk = bob.public_bytes();
    let plaintext = vec![0xABu8; 256];
    c.bench_function("payload_seal_256b", |b| {
        b.iter(|| {
            let nonce = random_nonce().unwrap();
            let _ct = payload::seal(
                std::hint::black_box(&plaintext),
                &alice,
                &bob_pk,
                &nonce,
                b"",
            )
            .unwrap();
        });
    });
}

fn bench_open(c: &mut Criterion) {
    let alice = fixture_side(0x05);
    let bob = fixture_side(0x06);
    let alice_pk = alice.public_bytes();
    let plaintext = vec![0xCDu8; 256];
    let nonce = random_nonce().unwrap();
    let ciphertext = payload::seal(&plaintext, &alice, &bob.public_bytes(), &nonce, b"").unwrap();
    c.bench_function("payload_open_256b", |b| {
        b.iter(|| {
            let _pt = payload::open(
                std::hint::black_box(&ciphertext),
                &bob,
                &alice_pk,
                &nonce,
                b"",
            )
            .unwrap();
        });
    });
}

criterion_group!(crypto, bench_sign, bench_verify, bench_seal, bench_open);
criterion_main!(crypto);
