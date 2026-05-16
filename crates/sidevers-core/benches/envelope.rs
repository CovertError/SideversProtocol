//! Phase 1.F1: envelope codec baseline.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use criterion::{Criterion, criterion_group, criterion_main};
use sidevers_core::envelope::random_nonce;
use sidevers_core::keys::{MasterKey, SideKey};
use sidevers_core::{Envelope, MessageType};

fn fixture_side(seed: u8) -> SideKey {
    let m = MasterKey::from_seed(&[seed; 32]);
    m.derive_side(&"bench".into()).unwrap()
}

fn sample_envelope() -> Envelope {
    let alice = fixture_side(0x10);
    Envelope::sign_with(
        MessageType::DIRECT_MESSAGE,
        &alice,
        None,
        vec![0xAB; 128],
        1_700_000_000,
        random_nonce().unwrap(),
    )
    .unwrap()
}

fn bench_envelope_encode(c: &mut Criterion) {
    let env = sample_envelope();
    c.bench_function("envelope_to_wire_bytes_128b_payload", |b| {
        b.iter(|| {
            let _ = std::hint::black_box(&env).to_wire_bytes();
        });
    });
}

fn bench_envelope_decode(c: &mut Criterion) {
    let env = sample_envelope();
    let wire = env.to_wire_bytes();
    c.bench_function("envelope_from_wire_bytes_128b_payload", |b| {
        b.iter(|| {
            let _ = Envelope::from_wire_bytes(std::hint::black_box(&wire)).unwrap();
        });
    });
}

criterion_group!(envelope, bench_envelope_encode, bench_envelope_decode);
criterion_main!(envelope);
