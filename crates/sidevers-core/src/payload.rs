//! Payload encryption (protocol spec §3.4).
//!
//! For unicast envelopes (`to` is set), the payload is encrypted to the
//! recipient's side public key using X25519 ECDH + HKDF-SHA-512 + ChaCha20-Poly1305.
//! The Ed25519/X25519 conversion follows RFC 7748 §5:
//!
//!   1. SHA-512 the Ed25519 seed (32 bytes → 64 bytes).
//!   2. Take the first 32 bytes; clamp per RFC 7748 (clear bits 0/1/2 of byte 0;
//!      clear bit 7 and set bit 6 of byte 31).
//!   3. That's the X25519 scalar.
//!
//! For the public-key side, Ed25519's Edwards point converts to Montgomery
//! form via the standard birational map; ed25519-dalek exposes this as
//! `VerifyingKey::to_montgomery()`.
//!
//! Key derivation per spec §3.4:
//!
//! ```text
//! shared = X25519(sender_x_priv, recipient_x_pub)
//! key    = HKDF-SHA-512(ikm  = shared,
//!                       salt = envelope.nonce,
//!                       info = "sidevers/v1/payload",
//!                       L    = 32)
//! ```
//!
//! Spec gap: §3.4 specifies key derivation but does NOT specify how the
//! 12-byte ChaCha20-Poly1305 nonce is derived from the 16-byte envelope
//! nonce. We use the first 12 bytes of the envelope nonce. This is the
//! simplest interpretation that gives unique (key, aead-nonce) pairs per
//! envelope; flagged here so the spec can clarify before review.

use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use sha2::{Digest, Sha512};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};

use crate::error::{Error, Result};
use crate::keys::{PUBLIC_KEY_LEN, PublicKey, SideKey};

/// HKDF info string for payload-key derivation. Spec §3.4.
const PAYLOAD_HKDF_INFO: &[u8] = b"sidevers/v1/payload";

/// Length of the ChaCha20-Poly1305 AEAD nonce (RFC 8439).
const AEAD_NONCE_LEN: usize = 12;

/// Derive the X25519 static secret from this side's Ed25519 seed (RFC 7748 §5).
fn x25519_secret_from_side(side: &SideKey) -> XStaticSecret {
    let seed = side.signing_key().to_bytes();
    let mut hash = Sha512::new();
    hash.update(seed);
    let digest = hash.finalize();
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&digest[..32]);
    // The x25519_dalek::StaticSecret::from constructor itself applies the
    // RFC 7748 clamping, so we can hand it the raw hash prefix.
    XStaticSecret::from(scalar)
}

/// Convert an Ed25519 public key into the corresponding X25519 public key,
/// using ed25519-dalek's built-in Edwards→Montgomery map.
fn x25519_public_from_ed25519(pk: &PublicKey) -> XPublicKey {
    let mont = pk.verifying_key().to_montgomery();
    XPublicKey::from(mont.to_bytes())
}

/// Compute the per-envelope ChaCha20-Poly1305 key for this (sender, recipient,
/// envelope-nonce) tuple per spec §3.4.
fn derive_aead_key(
    sender_side: &SideKey,
    recipient_pk: &PublicKey,
    envelope_nonce: &[u8; crate::envelope::NONCE_LEN],
) -> [u8; 32] {
    let secret = x25519_secret_from_side(sender_side);
    let public = x25519_public_from_ed25519(recipient_pk);
    let shared = secret.diffie_hellman(&public);

    let hkdf = Hkdf::<Sha512>::new(Some(envelope_nonce.as_slice()), shared.as_bytes());
    let mut key = [0u8; 32];
    // HKDF-SHA-512 expand only errors when the output length exceeds
    // 255 * HashLen (255 * 64 = 16,320 bytes). We request 32. So this
    // branch is unreachable in practice.
    #[allow(clippy::expect_used)]
    hkdf.expand(PAYLOAD_HKDF_INFO, &mut key)
        .expect("HKDF expand to 32 bytes cannot fail");
    key
}

fn aead_nonce_from_envelope_nonce(
    envelope_nonce: &[u8; crate::envelope::NONCE_LEN],
) -> [u8; AEAD_NONCE_LEN] {
    let mut n = [0u8; AEAD_NONCE_LEN];
    n.copy_from_slice(&envelope_nonce[..AEAD_NONCE_LEN]);
    n
}

/// Encrypt a payload to the recipient. The `aad` (additional authenticated
/// data) parameter binds the ciphertext to envelope context — pass the
/// envelope's `(version, message_type, from, to, ts)` to prevent
/// cross-envelope reuse. The spec doesn't mandate AAD; we use it defensively.
pub fn seal(
    plaintext: &[u8],
    sender_side: &SideKey,
    recipient_pk_bytes: &[u8; PUBLIC_KEY_LEN],
    envelope_nonce: &[u8; crate::envelope::NONCE_LEN],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let recipient_pk = PublicKey::from_bytes(recipient_pk_bytes)?;
    let key_bytes = derive_aead_key(sender_side, &recipient_pk, envelope_nonce);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    let nonce_bytes = aead_nonce_from_envelope_nonce(envelope_nonce);
    cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Invariant("AEAD encrypt failed"))
}

/// Decrypt a payload addressed to the recipient (this side). The `sender_pk_bytes`
/// is the envelope's `from` field, the `envelope_nonce` is the envelope's `nonce`,
/// and `aad` MUST be the same bytes the sender used (typically the envelope
/// header components).
pub fn open(
    ciphertext: &[u8],
    recipient_side: &SideKey,
    sender_pk_bytes: &[u8; PUBLIC_KEY_LEN],
    envelope_nonce: &[u8; crate::envelope::NONCE_LEN],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let sender_pk = PublicKey::from_bytes(sender_pk_bytes)?;
    // ECDH is symmetric: (sender_x_priv * recipient_x_pub) == (recipient_x_priv * sender_x_pub).
    let key_bytes = derive_aead_key(recipient_side, &sender_pk, envelope_nonce);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    let nonce_bytes = aead_nonce_from_envelope_nonce(envelope_nonce);
    cipher
        .decrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::NONCE_LEN;
    use crate::keys::MasterKey;

    fn alice_bob() -> (SideKey, SideKey) {
        let alice_m = MasterKey::from_seed(&[0x42u8; 32]);
        let bob_m = MasterKey::from_seed(&[0x99u8; 32]);
        let alice = alice_m.derive_side(&"private".into()).unwrap();
        let bob = bob_m.derive_side(&"close".into()).unwrap();
        (alice, bob)
    }

    #[test]
    fn seal_open_roundtrip() {
        let (alice, bob) = alice_bob();
        let bob_pk = bob.public_bytes();
        let alice_pk = alice.public_bytes();
        let nonce = [3u8; NONCE_LEN];
        let plaintext = b"hello sidevers";
        let aad = b"v1|0x20|ts=1000";

        let ct = seal(plaintext, &alice, &bob_pk, &nonce, aad).unwrap();
        assert_ne!(ct, plaintext);

        let pt = open(&ct, &bob, &alice_pk, &nonce, aad).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn wrong_recipient_fails_to_decrypt() {
        let (alice, _bob) = alice_bob();
        let stranger = MasterKey::generate()
            .unwrap()
            .derive_side(&"close".into())
            .unwrap();
        let nonce = [5u8; NONCE_LEN];
        let bob_pk = stranger.public_bytes(); // sender thinks they're sending to "bob"
        let ct = seal(b"secret", &alice, &bob_pk, &nonce, b"").unwrap();

        // A different recipient (not the intended bob_pk's owner) can't decrypt.
        let (alice2, _) = alice_bob();
        let err = open(&ct, &alice2, &alice.public_bytes(), &nonce, b"").unwrap_err();
        assert!(matches!(err, Error::DecryptionFailed));
    }

    #[test]
    fn tampered_ciphertext_fails_to_decrypt() {
        let (alice, bob) = alice_bob();
        let nonce = [1u8; NONCE_LEN];
        let mut ct = seal(b"hi", &alice, &bob.public_bytes(), &nonce, b"").unwrap();
        ct[0] ^= 0x01;
        assert!(open(&ct, &bob, &alice.public_bytes(), &nonce, b"").is_err());
    }

    #[test]
    fn aad_mismatch_fails_to_decrypt() {
        let (alice, bob) = alice_bob();
        let nonce = [1u8; NONCE_LEN];
        let ct = seal(b"hi", &alice, &bob.public_bytes(), &nonce, b"context-A").unwrap();
        assert!(open(&ct, &bob, &alice.public_bytes(), &nonce, b"context-B").is_err());
    }
}
