//! Storage preferences (protocol spec §5.7).
//!
//! Each side may publish a signed declaration of its preferences for how
//! its content-addressed objects should be stored: which peer-side
//! identities it would prefer act as storage providers (in order), a
//! ceiling on object size it expects providers to handle, and a hint
//! about retention. The declaration is signed by the declaring side so
//! anyone who has the bytes can verify the preference is authentic.
//!
//! Phase 1.G2 introduces this struct + its wire codec. Distribution
//! (whether to ride alongside ProfilePayload, gossip independently,
//! or be queried on demand) is left for Phase-2 spec refinement; this
//! crate ships the struct so callers can build / verify it today.
//!
//! Wire format (one CBOR map, six entries, RFC 8949 §4.2.1 canonical
//! key order):
//!
//!   side                : bstr (32 bytes, Ed25519 public key of declarer)
//!   signature           : bstr (64 bytes, Ed25519(side_priv, BLAKE3(unsigned)))
//!   updated_at          : uint (unix seconds)
//!   max_object_kib      : uint (size ceiling hint in KiB)
//!   preferred_providers : array of bstr (32 bytes each, ordered preference)
//!   retention_hint_secs : uint (how long the declarer wants objects retained)
//!
//! The "unsigned" body is the canonical-CBOR 5-entry sub-map omitting
//! `signature`.

use crate::cbor::{self, CborReader, CborWriter, MapEntry};
use crate::error::{Error, Result};
use crate::keys::{PUBLIC_KEY_LEN, PublicKey, SIGNATURE_LEN, SideKey};

/// A signed storage-preferences declaration for a side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoragePreferences {
    pub side: [u8; PUBLIC_KEY_LEN],
    pub preferred_providers: Vec<[u8; PUBLIC_KEY_LEN]>,
    pub max_object_kib: u64,
    pub retention_hint_secs: u64,
    pub updated_at: u64,
    pub signature: [u8; SIGNATURE_LEN],
}

impl StoragePreferences {
    /// Build the canonical CBOR of the unsigned body.
    fn encode_unsigned(
        side: &[u8; PUBLIC_KEY_LEN],
        updated_at: u64,
        max_object_kib: u64,
        preferred_providers: &[[u8; PUBLIC_KEY_LEN]],
        retention_hint_secs: u64,
    ) -> Vec<u8> {
        // Canonical key order (RFC 8949 §4.2.1, bytewise lex of
        // encoded keys, equivalent to length-first since all keys here
        // are short ASCII text strings):
        //   side, updated_at, max_object_kib, preferred_providers, retention_hint_secs
        let entries = [
            MapEntry {
                key: cbor::key("side"),
                value: cbor::bytes(side),
            },
            MapEntry {
                key: cbor::key("updated_at"),
                value: cbor::uint(updated_at),
            },
            MapEntry {
                key: cbor::key("max_object_kib"),
                value: cbor::uint(max_object_kib),
            },
            MapEntry {
                key: cbor::key("preferred_providers"),
                value: encode_provider_array(preferred_providers),
            },
            MapEntry {
                key: cbor::key("retention_hint_secs"),
                value: cbor::uint(retention_hint_secs),
            },
        ];
        cbor::encode_map(&entries)
    }

    /// Sign a fresh preferences declaration. The signing key must be the
    /// side the declaration is for; the embedded `side` field is set
    /// from `side.public_bytes()` automatically.
    pub fn sign(
        side: &SideKey,
        updated_at: u64,
        max_object_kib: u64,
        preferred_providers: Vec<[u8; PUBLIC_KEY_LEN]>,
        retention_hint_secs: u64,
    ) -> Result<Self> {
        let pk = side.public_bytes();
        let unsigned = Self::encode_unsigned(
            &pk,
            updated_at,
            max_object_kib,
            &preferred_providers,
            retention_hint_secs,
        );
        let digest = blake3::hash(&unsigned);
        let signature = side.sign(digest.as_bytes());
        Ok(Self {
            side: pk,
            preferred_providers,
            max_object_kib,
            retention_hint_secs,
            updated_at,
            signature,
        })
    }

    /// Encode the full 6-entry signed record for the wire.
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let entries = [
            MapEntry {
                key: cbor::key("side"),
                value: cbor::bytes(&self.side),
            },
            MapEntry {
                key: cbor::key("signature"),
                value: cbor::bytes(&self.signature),
            },
            MapEntry {
                key: cbor::key("updated_at"),
                value: cbor::uint(self.updated_at),
            },
            MapEntry {
                key: cbor::key("max_object_kib"),
                value: cbor::uint(self.max_object_kib),
            },
            MapEntry {
                key: cbor::key("preferred_providers"),
                value: encode_provider_array(&self.preferred_providers),
            },
            MapEntry {
                key: cbor::key("retention_hint_secs"),
                value: cbor::uint(self.retention_hint_secs),
            },
        ];
        cbor::encode_map(&entries)
    }

    /// Parse + verify a preferences declaration from wire bytes.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = CborReader::new(bytes);
        let n = r.read_map_header()?;
        if n != 6 {
            return Err(Error::CborDecode(format!(
                "StoragePreferences expected 6 keys, got {n}"
            )));
        }
        let expected = [
            "side",
            "signature",
            "updated_at",
            "max_object_kib",
            "preferred_providers",
            "retention_hint_secs",
        ];
        let mut side: Option<[u8; PUBLIC_KEY_LEN]> = None;
        let mut signature: Option<[u8; SIGNATURE_LEN]> = None;
        let mut updated_at: Option<u64> = None;
        let mut max_object_kib: Option<u64> = None;
        let mut preferred_providers: Option<Vec<[u8; PUBLIC_KEY_LEN]>> = None;
        let mut retention_hint_secs: Option<u64> = None;
        for key in expected {
            let k = r.read_text()?;
            if k != key {
                return Err(Error::CborNotCanonical(
                    "StoragePreferences keys not in canonical order",
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
                "updated_at" => updated_at = Some(r.read_u64()?),
                "max_object_kib" => max_object_kib = Some(r.read_u64()?),
                "preferred_providers" => {
                    let len = r.read_array_header()?;
                    let mut out = Vec::with_capacity(len);
                    for _ in 0..len {
                        let b = r.read_bytes()?;
                        if b.len() != PUBLIC_KEY_LEN {
                            return Err(Error::BadFieldLength {
                                field: "preferred_providers[]",
                                expected: PUBLIC_KEY_LEN,
                                got: b.len(),
                            });
                        }
                        let mut arr = [0u8; PUBLIC_KEY_LEN];
                        arr.copy_from_slice(b);
                        out.push(arr);
                    }
                    preferred_providers = Some(out);
                }
                "retention_hint_secs" => retention_hint_secs = Some(r.read_u64()?),
                _ => unreachable!(),
            }
        }
        if !r.at_end() {
            return Err(Error::CborDecode(
                "trailing bytes after StoragePreferences".into(),
            ));
        }
        let side = side.ok_or(Error::Invariant("missing side"))?;
        let signature = signature.ok_or(Error::Invariant("missing signature"))?;
        let updated_at = updated_at.ok_or(Error::Invariant("missing updated_at"))?;
        let max_object_kib = max_object_kib.ok_or(Error::Invariant("missing max_object_kib"))?;
        let preferred_providers =
            preferred_providers.ok_or(Error::Invariant("missing preferred_providers"))?;
        let retention_hint_secs =
            retention_hint_secs.ok_or(Error::Invariant("missing retention_hint_secs"))?;

        let unsigned = Self::encode_unsigned(
            &side,
            updated_at,
            max_object_kib,
            &preferred_providers,
            retention_hint_secs,
        );
        let digest = blake3::hash(&unsigned);
        PublicKey::from_bytes(&side)?.verify(digest.as_bytes(), &signature)?;

        let payload = Self {
            side,
            preferred_providers,
            max_object_kib,
            retention_hint_secs,
            updated_at,
            signature,
        };
        if payload.to_wire_bytes() != bytes {
            return Err(Error::CborNotCanonical(
                "StoragePreferences bytes are not canonical re-encode",
            ));
        }
        Ok(payload)
    }
}

fn encode_provider_array(providers: &[[u8; PUBLIC_KEY_LEN]]) -> Vec<u8> {
    let mut w = CborWriter::new();
    w.write_array_header(providers.len());
    for pk in providers {
        w.write_bytes(pk);
    }
    w.into_bytes()
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
    fn storage_prefs_signed_round_trip() {
        let side = fixture_side(0x42);
        let providers = vec![[0xAA; PUBLIC_KEY_LEN], [0xBB; PUBLIC_KEY_LEN]];
        let p = StoragePreferences::sign(&side, 1_700_000_000, 1024, providers.clone(), 86_400)
            .unwrap();
        let bytes = p.to_wire_bytes();
        let parsed = StoragePreferences::from_wire_bytes(&bytes).unwrap();
        assert_eq!(parsed, p);
        assert_eq!(parsed.preferred_providers, providers);
        assert_eq!(parsed.max_object_kib, 1024);
        assert_eq!(parsed.retention_hint_secs, 86_400);
    }

    #[test]
    fn storage_prefs_empty_providers_round_trips() {
        let side = fixture_side(0x10);
        let p = StoragePreferences::sign(&side, 100, 512, Vec::new(), 60).unwrap();
        let bytes = p.to_wire_bytes();
        let parsed = StoragePreferences::from_wire_bytes(&bytes).unwrap();
        assert!(parsed.preferred_providers.is_empty());
        assert_eq!(parsed, p);
    }

    #[test]
    fn tampered_storage_prefs_fails_verification() {
        let side = fixture_side(0x99);
        let mut p = StoragePreferences::sign(&side, 500, 256, Vec::new(), 600).unwrap();
        p.signature[0] ^= 0xFF;
        let bytes = p.to_wire_bytes();
        let err = StoragePreferences::from_wire_bytes(&bytes).unwrap_err();
        assert!(matches!(err, Error::SignatureInvalid));
    }
}
