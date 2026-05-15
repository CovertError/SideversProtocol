//! Linkage proofs (protocol spec §2.7).
//!
//! When a user wants to publicly establish that two sides belong to the same
//! person, they generate a linkage proof: a small CBOR record naming both
//! sides, signed by *both* sides' private keys. Anyone holding the proof can
//! verify that the two sides agreed to be linked; nobody can produce one
//! without both private keys.
//!
//! Per spec §2.7, the master key is NEVER involved in the linkage proof.
//! The master remains private even when the user is publicly linking sides.
//!
//! Wire format (one CBOR map, six entries, in canonical key order):
//!
//!   nonce     : bstr  (16 random bytes)
//!   sig_a     : bstr  (64 bytes, Ed25519(side_a_priv, BLAKE3(unsigned)))
//!   sig_b     : bstr  (64 bytes, Ed25519(side_b_priv, BLAKE3(unsigned)))
//!   side_a    : bstr  (32 bytes, Ed25519 public key)
//!   side_b    : bstr  (32 bytes, Ed25519 public key)
//!   issued_at : uint  (unix seconds)
//!
//! The "unsigned" bytes hashed to produce both signatures are the
//! canonical-CBOR encoding of the 4-entry sub-map {nonce, side_a, side_b, issued_at}.

use crate::cbor::{self, CborReader, MapEntry};
use crate::error::{Error, Result};
use crate::keys::{PUBLIC_KEY_LEN, PublicKey, SIGNATURE_LEN, SideKey};

/// Length of the linkage-proof nonce in bytes.
pub const LINKAGE_NONCE_LEN: usize = 16;

/// A fully signed linkage proof, ready to publish or verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkageProof {
    pub side_a: [u8; PUBLIC_KEY_LEN],
    pub side_b: [u8; PUBLIC_KEY_LEN],
    pub issued_at: u64,
    pub nonce: [u8; LINKAGE_NONCE_LEN],
    pub sig_a: [u8; SIGNATURE_LEN],
    pub sig_b: [u8; SIGNATURE_LEN],
}

impl LinkageProof {
    /// Build the canonical CBOR encoding of the unsigned proof body — the
    /// 4-entry sub-map both signatures are computed over.
    fn encode_unsigned(
        nonce: &[u8; LINKAGE_NONCE_LEN],
        side_a: &[u8; PUBLIC_KEY_LEN],
        side_b: &[u8; PUBLIC_KEY_LEN],
        issued_at: u64,
    ) -> Vec<u8> {
        let entries = [
            MapEntry {
                key: cbor::key("nonce"),
                value: cbor::bytes(nonce),
            },
            MapEntry {
                key: cbor::key("side_a"),
                value: cbor::bytes(side_a),
            },
            MapEntry {
                key: cbor::key("side_b"),
                value: cbor::bytes(side_b),
            },
            MapEntry {
                key: cbor::key("issued_at"),
                value: cbor::uint(issued_at),
            },
        ];
        cbor::encode_map(&entries)
    }

    /// Sign a fresh linkage proof. Both sides MUST belong to the caller.
    pub fn sign(side_a: &SideKey, side_b: &SideKey, issued_at: u64) -> Result<Self> {
        let mut nonce = [0u8; LINKAGE_NONCE_LEN];
        getrandom::getrandom(&mut nonce).map_err(|e| Error::CsprngUnavailable(e.to_string()))?;
        Self::sign_with(side_a, side_b, issued_at, nonce)
    }

    /// Like `sign`, but with a caller-supplied nonce (deterministic tests).
    pub fn sign_with(
        side_a: &SideKey,
        side_b: &SideKey,
        issued_at: u64,
        nonce: [u8; LINKAGE_NONCE_LEN],
    ) -> Result<Self> {
        let a_pk = side_a.public_bytes();
        let b_pk = side_b.public_bytes();
        let unsigned = Self::encode_unsigned(&nonce, &a_pk, &b_pk, issued_at);
        let digest = blake3::hash(&unsigned);
        let sig_a = side_a.sign(digest.as_bytes());
        let sig_b = side_b.sign(digest.as_bytes());
        Ok(Self {
            side_a: a_pk,
            side_b: b_pk,
            issued_at,
            nonce,
            sig_a,
            sig_b,
        })
    }

    /// Encode the full 6-entry signed proof for the wire.
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let entries = [
            MapEntry {
                key: cbor::key("nonce"),
                value: cbor::bytes(&self.nonce),
            },
            MapEntry {
                key: cbor::key("sig_a"),
                value: cbor::bytes(&self.sig_a),
            },
            MapEntry {
                key: cbor::key("sig_b"),
                value: cbor::bytes(&self.sig_b),
            },
            MapEntry {
                key: cbor::key("side_a"),
                value: cbor::bytes(&self.side_a),
            },
            MapEntry {
                key: cbor::key("side_b"),
                value: cbor::bytes(&self.side_b),
            },
            MapEntry {
                key: cbor::key("issued_at"),
                value: cbor::uint(self.issued_at),
            },
        ];
        cbor::encode_map(&entries)
    }

    /// Parse and verify a linkage proof from wire bytes. Both signatures
    /// must verify; either failure aborts.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = CborReader::new(bytes);
        let n = r.read_map_header()?;
        if n != 6 {
            return Err(Error::CborDecode(format!(
                "LinkageProof expected 6 keys, got {n}"
            )));
        }
        let expected = ["nonce", "sig_a", "sig_b", "side_a", "side_b", "issued_at"];
        let mut nonce: Option<[u8; LINKAGE_NONCE_LEN]> = None;
        let mut sig_a: Option<[u8; SIGNATURE_LEN]> = None;
        let mut sig_b: Option<[u8; SIGNATURE_LEN]> = None;
        let mut side_a: Option<[u8; PUBLIC_KEY_LEN]> = None;
        let mut side_b: Option<[u8; PUBLIC_KEY_LEN]> = None;
        let mut issued_at: Option<u64> = None;
        for e in expected {
            let k = r.read_text()?;
            if k != e {
                return Err(Error::CborNotCanonical(
                    "LinkageProof keys not in canonical order",
                ));
            }
            match e {
                "nonce" => {
                    let b = r.read_bytes()?;
                    if b.len() != LINKAGE_NONCE_LEN {
                        return Err(Error::BadFieldLength {
                            field: "nonce",
                            expected: LINKAGE_NONCE_LEN,
                            got: b.len(),
                        });
                    }
                    let mut arr = [0u8; LINKAGE_NONCE_LEN];
                    arr.copy_from_slice(b);
                    nonce = Some(arr);
                }
                "sig_a" | "sig_b" => {
                    let b = r.read_bytes()?;
                    if b.len() != SIGNATURE_LEN {
                        return Err(Error::BadFieldLength {
                            field: if e == "sig_a" { "sig_a" } else { "sig_b" },
                            expected: SIGNATURE_LEN,
                            got: b.len(),
                        });
                    }
                    let mut arr = [0u8; SIGNATURE_LEN];
                    arr.copy_from_slice(b);
                    if e == "sig_a" {
                        sig_a = Some(arr);
                    } else {
                        sig_b = Some(arr);
                    }
                }
                "side_a" | "side_b" => {
                    let b = r.read_bytes()?;
                    if b.len() != PUBLIC_KEY_LEN {
                        return Err(Error::BadFieldLength {
                            field: if e == "side_a" { "side_a" } else { "side_b" },
                            expected: PUBLIC_KEY_LEN,
                            got: b.len(),
                        });
                    }
                    let mut arr = [0u8; PUBLIC_KEY_LEN];
                    arr.copy_from_slice(b);
                    if e == "side_a" {
                        side_a = Some(arr);
                    } else {
                        side_b = Some(arr);
                    }
                }
                "issued_at" => issued_at = Some(r.read_u64()?),
                _ => unreachable!(),
            }
        }
        if !r.at_end() {
            return Err(Error::CborDecode(
                "trailing bytes after LinkageProof".into(),
            ));
        }
        let nonce = nonce.ok_or(Error::Invariant("missing nonce"))?;
        let sig_a = sig_a.ok_or(Error::Invariant("missing sig_a"))?;
        let sig_b = sig_b.ok_or(Error::Invariant("missing sig_b"))?;
        let side_a = side_a.ok_or(Error::Invariant("missing side_a"))?;
        let side_b = side_b.ok_or(Error::Invariant("missing side_b"))?;
        let issued_at = issued_at.ok_or(Error::Invariant("missing issued_at"))?;

        let unsigned = Self::encode_unsigned(&nonce, &side_a, &side_b, issued_at);
        let digest = blake3::hash(&unsigned);
        PublicKey::from_bytes(&side_a)?.verify(digest.as_bytes(), &sig_a)?;
        PublicKey::from_bytes(&side_b)?.verify(digest.as_bytes(), &sig_b)?;

        let proof = Self {
            side_a,
            side_b,
            issued_at,
            nonce,
            sig_a,
            sig_b,
        };

        if proof.to_wire_bytes() != bytes {
            return Err(Error::CborNotCanonical(
                "LinkageProof bytes are not canonical re-encode",
            ));
        }

        Ok(proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::MasterKey;

    #[test]
    fn sign_and_verify_linkage_round_trip() {
        let master = MasterKey::from_seed(&[0x11u8; 32]);
        let public = master.derive_side(&"public".into()).unwrap();
        let private = master.derive_side(&"private".into()).unwrap();
        let proof = LinkageProof::sign(&public, &private, 1_700_000_000).unwrap();

        let bytes = proof.to_wire_bytes();
        let parsed = LinkageProof::from_wire_bytes(&bytes).unwrap();
        assert_eq!(parsed, proof);
    }

    #[test]
    fn cannot_forge_linkage_with_only_one_side() {
        let master_a = MasterKey::from_seed(&[0x11u8; 32]);
        let master_b = MasterKey::from_seed(&[0x22u8; 32]);
        let side_a = master_a.derive_side(&"work".into()).unwrap();
        let side_b = master_b.derive_side(&"work".into()).unwrap();
        // Two different people can sign a linkage proof; both signatures still verify.
        // But one party cannot produce a valid proof for a side they don't own.
        let proof = LinkageProof::sign(&side_a, &side_b, 1).unwrap();
        let bytes = proof.to_wire_bytes();
        let parsed = LinkageProof::from_wire_bytes(&bytes).unwrap();
        assert_eq!(parsed.side_a, side_a.public_bytes());
        assert_eq!(parsed.side_b, side_b.public_bytes());

        // If we tamper with sig_b (simulating someone trying to claim a link
        // they didn't sign for), verification fails.
        let mut tampered = proof.clone();
        tampered.sig_b[0] ^= 0x55;
        let bytes = tampered.to_wire_bytes();
        let err = LinkageProof::from_wire_bytes(&bytes).unwrap_err();
        assert!(matches!(err, Error::SignatureInvalid));
    }

    #[test]
    fn nonce_changes_each_signing() {
        let m = MasterKey::generate().unwrap();
        let s1 = m.derive_side(&"a".into()).unwrap();
        let s2 = m.derive_side(&"b".into()).unwrap();
        let p1 = LinkageProof::sign(&s1, &s2, 100).unwrap();
        let p2 = LinkageProof::sign(&s1, &s2, 100).unwrap();
        // Same parties, same timestamp — nonce differs, so digests differ,
        // so signatures differ.
        assert_ne!(p1.nonce, p2.nonce);
        assert_ne!(p1.sig_a, p2.sig_a);
    }
}
