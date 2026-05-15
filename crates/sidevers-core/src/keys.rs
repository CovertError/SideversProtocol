//! Identity keys (protocol spec §2).
//!
//! Each person has a **master keypair** (Ed25519, generated once on-device).
//! The master is never used to sign protocol messages; it only derives **sides**.
//! Each side is a per-label HKDF-SHA-512 derivation of the master, producing
//! an independent Ed25519 keypair. The set of side labels never leaves the
//! device; on the wire a side is identified solely by its public key.
//!
//! Key zeroization: secret material implements `Zeroize` and elides bytes
//! from `Debug` output. The master MUST be stored encrypted at rest by
//! callers; this module does not implement at-rest encryption.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::Zeroize;

use crate::error::{Error, Result};

/// HKDF salt for side derivation. Spec §2.4.
pub(crate) const SIDE_HKDF_SALT: &[u8] = b"sidevers/v1/sides";

/// Length of an Ed25519 seed / private-key bytes (§2.2).
pub const SECRET_KEY_LEN: usize = 32;

/// Length of an Ed25519 public key (§2.2).
pub const PUBLIC_KEY_LEN: usize = 32;

/// Length of an Ed25519 signature (§2.2).
pub const SIGNATURE_LEN: usize = 64;

/// A side label is an opaque UTF-8 byte string chosen by the user
/// (e.g., "private", "work", "close"). Spec §2.4 — labels are local-only,
/// never transmitted.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SideLabel(String);

impl SideLabel {
    pub fn new(label: impl Into<String>) -> Self {
        Self(label.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl core::fmt::Debug for SideLabel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Labels are not secret per se but they are local-only state, so
        // we keep them out of accidental Display contexts (e.g. logging).
        f.debug_struct("SideLabel").finish_non_exhaustive()
    }
}

impl From<&str> for SideLabel {
    fn from(s: &str) -> Self {
        SideLabel(s.to_owned())
    }
}

impl From<String> for SideLabel {
    fn from(s: String) -> Self {
        SideLabel(s)
    }
}

/// The user's master keypair. Per §2.3:
///   * Generated from the OS CSPRNG (`getrandom`) on first run.
///   * Never used to sign protocol messages directly.
///   * Stored encrypted at rest; this struct holds it in cleartext in memory.
///
/// `SigningKey` implements `ZeroizeOnDrop` internally (via curve25519-dalek's
/// `Scalar` zeroize), so dropping a `MasterKey` wipes the secret material.
pub struct MasterKey {
    signing: SigningKey,
}

impl MasterKey {
    /// Generate a new master keypair from the OS CSPRNG. Per §2.3, if the
    /// CSPRNG is unavailable we MUST refuse.
    pub fn generate() -> Result<Self> {
        let mut seed = [0u8; SECRET_KEY_LEN];
        getrandom::getrandom(&mut seed).map_err(|e| Error::CsprngUnavailable(e.to_string()))?;
        let signing = SigningKey::from_bytes(&seed);
        seed.zeroize();
        Ok(Self { signing })
    }

    /// Reconstruct a master from its 32-byte secret seed.
    /// Use only when restoring from at-rest storage.
    pub fn from_seed(seed: &[u8; SECRET_KEY_LEN]) -> Self {
        Self {
            signing: SigningKey::from_bytes(seed),
        }
    }

    /// Return the master's public key.
    pub fn public(&self) -> PublicKey {
        PublicKey(self.signing.verifying_key())
    }

    /// Export the secret seed. Caller is responsible for zeroizing.
    pub fn to_seed(&self) -> [u8; SECRET_KEY_LEN] {
        self.signing.to_bytes()
    }

    /// Derive a side from this master under the given label (§2.4).
    pub fn derive_side(&self, label: &SideLabel) -> Result<SideKey> {
        let ikm = self.signing.to_bytes();
        let hkdf = Hkdf::<Sha512>::new(Some(SIDE_HKDF_SALT), &ikm);
        // `ikm` is on the stack from to_bytes(); we want it gone fast.
        let mut ikm_zero = ikm;
        ikm_zero.zeroize();

        let mut side_seed = [0u8; SECRET_KEY_LEN];
        hkdf.expand(label.as_bytes(), &mut side_seed)
            .map_err(|_| Error::Invariant("HKDF expand failed (impossible at 32 bytes)"))?;
        let signing = SigningKey::from_bytes(&side_seed);
        side_seed.zeroize();
        Ok(SideKey {
            signing,
            label: label.clone(),
        })
    }
}

impl core::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MasterKey")
            .field("public", &self.public())
            .finish_non_exhaustive()
    }
}

/// A side (derived from a master). Holds its private key and the local label.
/// `SigningKey` zeroizes on drop (see `MasterKey` doc-comment).
pub struct SideKey {
    signing: SigningKey,
    label: SideLabel,
}

impl SideKey {
    /// Construct a side directly from a 32-byte seed. Use only for testing
    /// or restoring from at-rest storage; in normal operation sides come
    /// from `MasterKey::derive_side`.
    pub fn from_seed(seed: &[u8; SECRET_KEY_LEN], label: impl Into<SideLabel>) -> Self {
        Self {
            signing: SigningKey::from_bytes(seed),
            label: label.into(),
        }
    }

    pub fn label(&self) -> &SideLabel {
        &self.label
    }

    pub fn public(&self) -> PublicKey {
        PublicKey(self.signing.verifying_key())
    }

    pub fn public_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.signing.verifying_key().to_bytes()
    }

    pub fn to_seed(&self) -> [u8; SECRET_KEY_LEN] {
        self.signing.to_bytes()
    }

    /// Sign a digest (typically `BLAKE3(envelope-without-sig)` per §3.3).
    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.signing.sign(message).to_bytes()
    }

    /// Access to the underlying signing key for crate-internal uses that need
    /// the more specialized API (e.g., X25519 conversion).
    pub(crate) fn signing_key(&self) -> &SigningKey {
        &self.signing
    }
}

impl core::fmt::Debug for SideKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SideKey")
            .field("public", &self.public())
            .finish_non_exhaustive()
    }
}

/// An Ed25519 public key. Identifies a side or verse on the wire.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey(pub(crate) VerifyingKey);

impl PublicKey {
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_LEN]) -> Result<Self> {
        VerifyingKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| Error::Invariant("invalid Ed25519 public key encoding"))
    }

    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.0.to_bytes()
    }

    /// Verify a 64-byte signature against this public key.
    pub fn verify(&self, message: &[u8], signature: &[u8; SIGNATURE_LEN]) -> Result<()> {
        let sig = Signature::from_bytes(signature);
        self.0
            .verify(message, &sig)
            .map_err(|_| Error::SignatureInvalid)
    }

    pub(crate) fn verifying_key(&self) -> &VerifyingKey {
        &self.0
    }
}

impl core::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PublicKey({})", hex::encode(self.to_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn master_generates_and_derives_independent_sides() {
        let master = MasterKey::generate().unwrap();
        let work = master.derive_side(&"work".into()).unwrap();
        let close = master.derive_side(&"close".into()).unwrap();

        // Different labels produce different keys.
        assert_ne!(work.public_bytes(), close.public_bytes());
        // Neither side equals the master's own public key.
        assert_ne!(work.public_bytes(), master.public().to_bytes());
        assert_ne!(close.public_bytes(), master.public().to_bytes());
    }

    #[test]
    fn side_derivation_is_deterministic() {
        let seed = [7u8; 32];
        let master_a = MasterKey::from_seed(&seed);
        let master_b = MasterKey::from_seed(&seed);
        let side_a = master_a.derive_side(&"work".into()).unwrap();
        let side_b = master_b.derive_side(&"work".into()).unwrap();
        assert_eq!(side_a.public_bytes(), side_b.public_bytes());
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let master = MasterKey::generate().unwrap();
        let side = master.derive_side(&"private".into()).unwrap();
        let msg = b"hello sidevers";
        let sig = side.sign(msg);
        let pk = side.public();
        pk.verify(msg, &sig).unwrap();

        // Wrong message fails.
        assert!(pk.verify(b"hello sidevers!", &sig).is_err());
    }

    #[test]
    fn wrong_public_key_rejects_signature() {
        let master = MasterKey::generate().unwrap();
        let side = master.derive_side(&"private".into()).unwrap();
        let other = master.derive_side(&"work".into()).unwrap();
        let msg = b"hi";
        let sig = side.sign(msg);
        assert!(other.public().verify(msg, &sig).is_err());
    }
}
