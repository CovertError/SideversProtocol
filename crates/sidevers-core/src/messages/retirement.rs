//! Side retirement records (protocol spec §7.8).
//!
//! A side publishes a signed retirement record when it intends to stop
//! generating new history. Peers honor the record by treating any
//! subsequent signed message from that side as anomalous (and surfacing a
//! warning) — the keys still cryptographically verify, but the side has
//! announced it is no longer in use.
//!
//! Wire format (one CBOR map, four entries, canonical key order — derived
//! by encoded-key bytewise lex per RFC 8949 §4.2.1):
//!
//!   side       : bstr (32 bytes, Ed25519 public key of the retiring side)
//!   reason     : tstr / nil (optional short human-readable reason)
//!   signature  : bstr (64 bytes, Ed25519(side_priv, BLAKE3(unsigned)))
//!   retired_at : uint (unix seconds)
//!
//! The "unsigned" form hashed to produce the signature is the canonical
//! CBOR encoding of the 3-entry sub-map {side, reason, retired_at} (i.e.
//! the four-entry wire form minus `signature`).

use crate::cbor::{self, CborReader, MapEntry};
use crate::error::{Error, Result};
use crate::keys::{PUBLIC_KEY_LEN, PublicKey, SIGNATURE_LEN, SideKey};

/// A signed retirement record for a side, ready to publish or verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SideRetirementPayload {
    pub side: [u8; PUBLIC_KEY_LEN],
    pub reason: Option<String>,
    pub retired_at: u64,
    pub signature: [u8; SIGNATURE_LEN],
}

impl SideRetirementPayload {
    /// Build the canonical CBOR of the unsigned body — the 3-entry sub-map
    /// the signature is computed over.
    fn encode_unsigned(
        side: &[u8; PUBLIC_KEY_LEN],
        reason: Option<&str>,
        retired_at: u64,
    ) -> Vec<u8> {
        let entries = [
            MapEntry {
                key: cbor::key("side"),
                value: cbor::bytes(side),
            },
            MapEntry {
                key: cbor::key("reason"),
                value: match reason {
                    Some(s) => cbor::text(s),
                    None => cbor::null(),
                },
            },
            MapEntry {
                key: cbor::key("retired_at"),
                value: cbor::uint(retired_at),
            },
        ];
        cbor::encode_map(&entries)
    }

    /// Sign a fresh retirement record. The signing key must be the side that
    /// is retiring; the record names its own public key, and the signature
    /// is verifiable by anyone holding that public key.
    pub fn sign(side: &SideKey, retired_at: u64, reason: Option<String>) -> Result<Self> {
        let pk = side.public_bytes();
        let unsigned = Self::encode_unsigned(&pk, reason.as_deref(), retired_at);
        let digest = blake3::hash(&unsigned);
        let signature = side.sign(digest.as_bytes());
        Ok(Self {
            side: pk,
            reason,
            retired_at,
            signature,
        })
    }

    /// Encode the full 4-entry signed record for the wire.
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let entries = [
            MapEntry {
                key: cbor::key("side"),
                value: cbor::bytes(&self.side),
            },
            MapEntry {
                key: cbor::key("reason"),
                value: match &self.reason {
                    Some(s) => cbor::text(s),
                    None => cbor::null(),
                },
            },
            MapEntry {
                key: cbor::key("signature"),
                value: cbor::bytes(&self.signature),
            },
            MapEntry {
                key: cbor::key("retired_at"),
                value: cbor::uint(self.retired_at),
            },
        ];
        cbor::encode_map(&entries)
    }

    /// Parse + verify a retirement record from wire bytes. Rejects on any
    /// of: non-canonical CBOR, wrong key order, malformed field, or invalid
    /// signature.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = CborReader::new(bytes);
        let n = r.read_map_header()?;
        if n != 4 {
            return Err(Error::CborDecode(format!(
                "SideRetirement expected 4 keys, got {n}"
            )));
        }
        let expected = ["side", "reason", "signature", "retired_at"];
        let mut side: Option<[u8; PUBLIC_KEY_LEN]> = None;
        let mut reason: Option<Option<String>> = None;
        let mut signature: Option<[u8; SIGNATURE_LEN]> = None;
        let mut retired_at: Option<u64> = None;
        for key in expected {
            let k = r.read_text()?;
            if k != key {
                return Err(Error::CborNotCanonical(
                    "SideRetirement keys not in canonical order",
                ));
            }
            match key {
                "side" => {
                    let b = r.read_bytes()?;
                    if b.len() != PUBLIC_KEY_LEN {
                        return Err(Error::BadFieldLength {
                            field: "side",
                            expected: PUBLIC_KEY_LEN,
                            got: b.len(),
                        });
                    }
                    let mut arr = [0u8; PUBLIC_KEY_LEN];
                    arr.copy_from_slice(b);
                    side = Some(arr);
                }
                "reason" => {
                    // Reason is `tstr / nil`. Peek the next byte to choose.
                    let peek = *r
                        .remaining()
                        .first()
                        .ok_or_else(|| Error::CborDecode("missing reason".into()))?;
                    if peek == 0xF6 {
                        // CBOR null
                        let _ = r.read_bytes_or_null()?;
                        reason = Some(None);
                    } else {
                        let s = r.read_text()?.to_owned();
                        reason = Some(Some(s));
                    }
                }
                "signature" => {
                    let b = r.read_bytes()?;
                    if b.len() != SIGNATURE_LEN {
                        return Err(Error::BadFieldLength {
                            field: "signature",
                            expected: SIGNATURE_LEN,
                            got: b.len(),
                        });
                    }
                    let mut arr = [0u8; SIGNATURE_LEN];
                    arr.copy_from_slice(b);
                    signature = Some(arr);
                }
                "retired_at" => retired_at = Some(r.read_u64()?),
                _ => unreachable!(),
            }
        }
        if !r.at_end() {
            return Err(Error::CborDecode(
                "trailing bytes after SideRetirement".into(),
            ));
        }
        let side = side.ok_or(Error::Invariant("missing side"))?;
        let reason = reason.ok_or(Error::Invariant("missing reason"))?;
        let signature = signature.ok_or(Error::Invariant("missing signature"))?;
        let retired_at = retired_at.ok_or(Error::Invariant("missing retired_at"))?;

        let unsigned = Self::encode_unsigned(&side, reason.as_deref(), retired_at);
        let digest = blake3::hash(&unsigned);
        PublicKey::from_bytes(&side)?.verify(digest.as_bytes(), &signature)?;

        let payload = Self {
            side,
            reason,
            retired_at,
            signature,
        };

        if payload.to_wire_bytes() != bytes {
            return Err(Error::CborNotCanonical(
                "SideRetirement bytes are not canonical re-encode",
            ));
        }
        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::MasterKey;

    fn fixture_side(seed: u8) -> SideKey {
        let master = MasterKey::from_seed(&[seed; 32]);
        master.derive_side(&"work".into()).unwrap()
    }

    #[test]
    fn retirement_signed_round_trip() {
        let side = fixture_side(0x42);
        let payload = SideRetirementPayload::sign(
            &side,
            1_700_000_000,
            Some("moving to a new identity".to_owned()),
        )
        .unwrap();
        let bytes = payload.to_wire_bytes();
        let parsed = SideRetirementPayload::from_wire_bytes(&bytes).unwrap();
        assert_eq!(parsed, payload);
        assert_eq!(parsed.side, side.public_bytes());
        assert_eq!(parsed.retired_at, 1_700_000_000);
        assert_eq!(parsed.reason.as_deref(), Some("moving to a new identity"));
    }

    #[test]
    fn retirement_with_no_reason_round_trips() {
        let side = fixture_side(0x11);
        let payload = SideRetirementPayload::sign(&side, 42, None).unwrap();
        let bytes = payload.to_wire_bytes();
        let parsed = SideRetirementPayload::from_wire_bytes(&bytes).unwrap();
        assert_eq!(parsed, payload);
        assert!(parsed.reason.is_none());
    }

    #[test]
    fn tampered_retirement_signature_fails_verification() {
        let side = fixture_side(0x99);
        let mut payload = SideRetirementPayload::sign(&side, 100, None).unwrap();
        payload.signature[0] ^= 0xFF;
        let bytes = payload.to_wire_bytes();
        let err = SideRetirementPayload::from_wire_bytes(&bytes).unwrap_err();
        assert!(matches!(err, Error::SignatureInvalid));
    }

    #[test]
    fn tampered_retirement_field_fails_verification() {
        let side = fixture_side(0xAA);
        let payload = SideRetirementPayload::sign(&side, 500, None).unwrap();
        let mut bytes = payload.to_wire_bytes();
        // Flip a byte in the encoded retired_at value. (The exact position
        // depends on canonical encoding; find the value byte after the
        // "retired_at" key.)
        let key_marker = cbor::key("retired_at");
        let key_pos = bytes
            .windows(key_marker.len())
            .position(|w| w == key_marker)
            .expect("retired_at key in encoding");
        // Flip one byte of the value following the key. Walk past the key,
        // then past one byte of the uint head.
        let value_pos = key_pos + key_marker.len();
        bytes[value_pos] ^= 0x01;
        let err = SideRetirementPayload::from_wire_bytes(&bytes).unwrap_err();
        // Could surface as SignatureInvalid or CborNotCanonical depending on
        // whether the tampered byte changes the canonical form.
        assert!(
            matches!(err, Error::SignatureInvalid | Error::CborNotCanonical(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn retirement_rejects_wrong_signer() {
        // Manually construct a record where the `side` field doesn't match
        // the actual signer. Should fail verification.
        let real_signer = fixture_side(0x01);
        let claimed_pk = fixture_side(0x02).public_bytes();
        let unsigned = SideRetirementPayload::encode_unsigned(&claimed_pk, None, 999);
        let digest = blake3::hash(&unsigned);
        let forged_sig = real_signer.sign(digest.as_bytes());
        let payload = SideRetirementPayload {
            side: claimed_pk,
            reason: None,
            retired_at: 999,
            signature: forged_sig,
        };
        let bytes = payload.to_wire_bytes();
        let err = SideRetirementPayload::from_wire_bytes(&bytes).unwrap_err();
        assert!(matches!(err, Error::SignatureInvalid));
    }
}
