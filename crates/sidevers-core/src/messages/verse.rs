//! Verse payloads — Appendix A range 0x50–0x59 (§8.5–§8.9).
//!
//! Phase 1.5 implements the join + post path:
//!
//!   * 0x50 ContractFetch    — anyone → verse: "send me your contract"
//!   * 0x51 ContractDeliver  — verse → asker: signed ContractObject bytes
//!   * 0x52 JoinRequest      — prospective → verse: "I agree to this contract"
//!   * 0x53 JoinAccept       — verse → member: membership token + sealed content key
//!   * 0x54 JoinDecline      — verse → prospective: refused, with reason
//!   * 0x57 VersePost        — member → verse: verse-key-encrypted content
//!
//! 0x55 VerseLeave, 0x56 VerseRemove, 0x58 VerseAmend, 0x59 VerseReconsent
//! arrive later in Phase 1.5b together with verse-key rotation.

use std::collections::BTreeMap;

use crate::cbor::{self, CborReader, MapEntry};
use crate::error::{Error, Result};
use crate::keys::{PUBLIC_KEY_LEN, PublicKey, SIGNATURE_LEN, SideKey};
use crate::verse::{ContractObject, FieldKind};

// ============================================================================
// 0x50 ContractFetch
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractFetchPayload {
    /// Specific contract version to request; `None` = the verse's current.
    pub version: Option<u64>,
}

impl ContractFetchPayload {
    pub fn encode(&self) -> Vec<u8> {
        let entries = [MapEntry {
            key: cbor::text("version"),
            value: match self.version {
                Some(v) => cbor::uint(v),
                None => cbor::null(),
            },
        }];
        cbor::encode_map(&entries)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = CborReader::new(bytes);
        let n = r.read_map_header()?;
        if n != 1 {
            return Err(Error::CborDecode(format!(
                "ContractFetch expected 1 key, got {n}"
            )));
        }
        if r.read_text()? != "version" {
            return Err(Error::CborNotCanonical("ContractFetch expects 'version'"));
        }
        let peek = *r
            .remaining()
            .first()
            .ok_or_else(|| Error::CborDecode("missing version".into()))?;
        let version = if peek == 0xF6 {
            r.read_bytes_or_null()?;
            None
        } else {
            Some(r.read_u64()?)
        };
        Ok(Self { version })
    }
}

// ============================================================================
// 0x51 ContractDeliver — wraps a ContractObject for the wire
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractDeliverPayload {
    pub contract: ContractObject,
}

impl ContractDeliverPayload {
    pub fn encode(&self) -> Vec<u8> {
        let entries = [MapEntry {
            key: cbor::text("contract"),
            value: self.contract.to_wire_bytes(),
        }];
        cbor::encode_map(&entries)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = CborReader::new(bytes);
        let n = r.read_map_header()?;
        if n != 1 {
            return Err(Error::CborDecode(format!(
                "ContractDeliver expected 1 key, got {n}"
            )));
        }
        if r.read_text()? != "contract" {
            return Err(Error::CborNotCanonical(
                "ContractDeliver expects 'contract'",
            ));
        }
        let start = r.position();
        // The contract is itself a CBOR map; let from_wire_bytes consume it.
        let remaining_after_key = &bytes[start..];
        let contract = ContractObject::from_wire_bytes(remaining_after_key)?;
        Ok(Self { contract })
    }
}

// ============================================================================
// 0x52 JoinRequest
// ============================================================================

/// Fields a joining member is willing to share with the verse. Phase 1.5a
/// supports text values only (display-name, pronoun, etc.); future versions
/// can extend to images, structured credentials, etc.
pub type FieldValues = BTreeMap<FieldKind, String>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinRequestPayload {
    pub contract_hash: [u8; 32],
    pub side: [u8; PUBLIC_KEY_LEN],
    pub fields: FieldValues,
    /// Signed by the joining side over BLAKE3(unsigned encoding).
    pub signature: [u8; SIGNATURE_LEN],
}

impl JoinRequestPayload {
    /// Canonical key order: side < fields < signature < contract_hash.
    fn encode_unsigned(
        contract_hash: &[u8; 32],
        side: &[u8; PUBLIC_KEY_LEN],
        fields: &FieldValues,
    ) -> Vec<u8> {
        let entries = [
            MapEntry {
                key: cbor::text("side"),
                value: cbor::bytes(side),
            },
            MapEntry {
                key: cbor::text("fields"),
                value: encode_field_values(fields),
            },
            MapEntry {
                key: cbor::text("contract_hash"),
                value: cbor::bytes(contract_hash),
            },
        ];
        cbor::encode_map(&entries)
    }

    pub fn sign(side_key: &SideKey, contract_hash: [u8; 32], fields: FieldValues) -> Result<Self> {
        let side = side_key.public_bytes();
        let unsigned = Self::encode_unsigned(&contract_hash, &side, &fields);
        let digest = blake3::hash(&unsigned);
        let signature = side_key.sign(digest.as_bytes());
        Ok(Self {
            contract_hash,
            side,
            fields,
            signature,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let entries = [
            MapEntry {
                key: cbor::text("side"),
                value: cbor::bytes(&self.side),
            },
            MapEntry {
                key: cbor::text("fields"),
                value: encode_field_values(&self.fields),
            },
            MapEntry {
                key: cbor::text("signature"),
                value: cbor::bytes(&self.signature),
            },
            MapEntry {
                key: cbor::text("contract_hash"),
                value: cbor::bytes(&self.contract_hash),
            },
        ];
        cbor::encode_map(&entries)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = CborReader::new(bytes);
        let n = r.read_map_header()?;
        if n != 4 {
            return Err(Error::CborDecode(format!(
                "JoinRequest expected 4 keys, got {n}"
            )));
        }
        let expected = ["side", "fields", "signature", "contract_hash"];
        let mut side = None;
        let mut fields = None;
        let mut signature = None;
        let mut contract_hash = None;
        for e in expected {
            let k = r.read_text()?;
            if k != e {
                return Err(Error::CborNotCanonical(
                    "JoinRequest keys not in canonical order",
                ));
            }
            match e {
                "side" => side = Some(read_fixed_pubkey(&mut r, "side")?),
                "fields" => fields = Some(decode_field_values(&mut r)?),
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
                "contract_hash" => {
                    let b = r.read_bytes()?;
                    if b.len() != 32 {
                        return Err(Error::BadFieldLength {
                            field: "contract_hash",
                            expected: 32,
                            got: b.len(),
                        });
                    }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(b);
                    contract_hash = Some(arr);
                }
                _ => unreachable!(),
            }
        }
        let side = side.ok_or(Error::Invariant("missing side"))?;
        let fields = fields.ok_or(Error::Invariant("missing fields"))?;
        let signature = signature.ok_or(Error::Invariant("missing signature"))?;
        let contract_hash = contract_hash.ok_or(Error::Invariant("missing contract_hash"))?;

        let unsigned = Self::encode_unsigned(&contract_hash, &side, &fields);
        let digest = blake3::hash(&unsigned);
        PublicKey::from_bytes(&side)?.verify(digest.as_bytes(), &signature)?;

        Ok(Self {
            contract_hash,
            side,
            fields,
            signature,
        })
    }
}

// ============================================================================
// 0x53 JoinAccept — carries the membership token AND the sealed content key
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinAcceptPayload {
    /// Encoded `MembershipToken` (signed by the verse) — verifiable standalone.
    pub membership_token: Vec<u8>,
    /// AEAD nonce used to seal the verse content key to the joining side.
    pub key_nonce: [u8; 16],
    /// ChaCha20-Poly1305 ciphertext of the 32-byte verse content key,
    /// derived via X25519 ECDH between the verse's keypair and the joining
    /// side's X25519 public key (per spec §3.4 / §8.6.1).
    pub sealed_content_key: Vec<u8>,
}

impl JoinAcceptPayload {
    /// Canonical key order: key_nonce (0x69…) < membership_token (0x70…)
    /// < sealed_content_key (0x72…).
    pub fn encode(&self) -> Vec<u8> {
        let entries = [
            MapEntry {
                key: cbor::text("key_nonce"),
                value: cbor::bytes(&self.key_nonce),
            },
            MapEntry {
                key: cbor::text("membership_token"),
                value: cbor::bytes(&self.membership_token),
            },
            MapEntry {
                key: cbor::text("sealed_content_key"),
                value: cbor::bytes(&self.sealed_content_key),
            },
        ];
        cbor::encode_map(&entries)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = CborReader::new(bytes);
        let n = r.read_map_header()?;
        if n != 3 {
            return Err(Error::CborDecode(format!(
                "JoinAccept expected 3 keys, got {n}"
            )));
        }
        if r.read_text()? != "key_nonce" {
            return Err(Error::CborNotCanonical("expected 'key_nonce' first"));
        }
        let b = r.read_bytes()?;
        if b.len() != 16 {
            return Err(Error::BadFieldLength {
                field: "key_nonce",
                expected: 16,
                got: b.len(),
            });
        }
        let mut key_nonce = [0u8; 16];
        key_nonce.copy_from_slice(b);
        if r.read_text()? != "membership_token" {
            return Err(Error::CborNotCanonical(
                "expected 'membership_token' second",
            ));
        }
        let membership_token = r.read_bytes()?.to_vec();
        if r.read_text()? != "sealed_content_key" {
            return Err(Error::CborNotCanonical(
                "expected 'sealed_content_key' third",
            ));
        }
        let sealed_content_key = r.read_bytes()?.to_vec();
        Ok(Self {
            membership_token,
            key_nonce,
            sealed_content_key,
        })
    }
}

// ============================================================================
// 0x54 JoinDecline
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinDeclinePayload {
    pub contract_hash: [u8; 32],
    pub reason: String,
}

impl JoinDeclinePayload {
    pub fn encode(&self) -> Vec<u8> {
        // Canonical: reason (0x66…) < contract_hash (0x6d…).
        let entries = [
            MapEntry {
                key: cbor::text("reason"),
                value: cbor::text(&self.reason),
            },
            MapEntry {
                key: cbor::text("contract_hash"),
                value: cbor::bytes(&self.contract_hash),
            },
        ];
        cbor::encode_map(&entries)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = CborReader::new(bytes);
        let n = r.read_map_header()?;
        if n != 2 {
            return Err(Error::CborDecode(format!(
                "JoinDecline expected 2 keys, got {n}"
            )));
        }
        if r.read_text()? != "reason" {
            return Err(Error::CborNotCanonical("expected 'reason' first"));
        }
        let reason = r.read_text()?.to_owned();
        if r.read_text()? != "contract_hash" {
            return Err(Error::CborNotCanonical("expected 'contract_hash' second"));
        }
        let b = r.read_bytes()?;
        if b.len() != 32 {
            return Err(Error::BadFieldLength {
                field: "contract_hash",
                expected: 32,
                got: b.len(),
            });
        }
        let mut contract_hash = [0u8; 32];
        contract_hash.copy_from_slice(b);
        Ok(Self {
            contract_hash,
            reason,
        })
    }
}

// ============================================================================
// 0x57 VersePost — verse-key-encrypted content
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersePostPayload {
    /// AEAD nonce for the verse content key. 12 bytes.
    pub nonce: [u8; 12],
    /// ChaCha20-Poly1305 ciphertext of the post body.
    pub ciphertext: Vec<u8>,
}

impl VersePostPayload {
    pub fn encode(&self) -> Vec<u8> {
        // Canonical: nonce (0x65…) < ciphertext (0x6a…).
        let entries = [
            MapEntry {
                key: cbor::text("nonce"),
                value: cbor::bytes(&self.nonce),
            },
            MapEntry {
                key: cbor::text("ciphertext"),
                value: cbor::bytes(&self.ciphertext),
            },
        ];
        cbor::encode_map(&entries)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = CborReader::new(bytes);
        let n = r.read_map_header()?;
        if n != 2 {
            return Err(Error::CborDecode(format!(
                "VersePost expected 2 keys, got {n}"
            )));
        }
        if r.read_text()? != "nonce" {
            return Err(Error::CborNotCanonical("expected 'nonce' first"));
        }
        let b = r.read_bytes()?;
        if b.len() != 12 {
            return Err(Error::BadFieldLength {
                field: "nonce",
                expected: 12,
                got: b.len(),
            });
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(b);
        if r.read_text()? != "ciphertext" {
            return Err(Error::CborNotCanonical("expected 'ciphertext' second"));
        }
        let ciphertext = r.read_bytes()?.to_vec();
        Ok(Self { nonce, ciphertext })
    }
}

// ============================================================================
// DataDisposition (§8.8)
// ============================================================================

/// What the departing member asks the verse to do with their past content.
/// Per spec §8.8 this is advisory — the protocol can ask, not compel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataDisposition {
    Retain,
    Retract,
    Transfer,
}

impl DataDisposition {
    pub fn as_str(self) -> &'static str {
        match self {
            DataDisposition::Retain => "retain",
            DataDisposition::Retract => "retract",
            DataDisposition::Transfer => "transfer",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "retain" => Ok(DataDisposition::Retain),
            "retract" => Ok(DataDisposition::Retract),
            "transfer" => Ok(DataDisposition::Transfer),
            other => Err(Error::CborDecode(format!(
                "unknown DataDisposition '{other}'"
            ))),
        }
    }
}

// ============================================================================
// 0x55 VerseLeave (§8.8)
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerseLeavePayload {
    pub verse: [u8; PUBLIC_KEY_LEN],
    pub side: [u8; PUBLIC_KEY_LEN],
    pub membership_hash: [u8; 32],
    pub reason: Option<String>,
    pub disposition: DataDisposition,
    /// Signed by the departing side over BLAKE3(unsigned encoding).
    pub signature: [u8; SIGNATURE_LEN],
}

impl VerseLeavePayload {
    /// Canonical key order (bytewise on encoded keys):
    ///   side (0x64) < verse (0x65) < reason (0x66) < disposition (0x6b)
    ///   < membership_hash (0x6f)
    /// The "unsigned" form is signed by the leaving side; signature goes
    /// between disposition and membership_hash (0x69) on the wire.
    fn encode_unsigned(
        verse: &[u8; PUBLIC_KEY_LEN],
        side: &[u8; PUBLIC_KEY_LEN],
        membership_hash: &[u8; 32],
        reason: Option<&str>,
        disposition: DataDisposition,
    ) -> Vec<u8> {
        let entries = [
            MapEntry {
                key: cbor::text("side"),
                value: cbor::bytes(side),
            },
            MapEntry {
                key: cbor::text("verse"),
                value: cbor::bytes(verse),
            },
            MapEntry {
                key: cbor::text("reason"),
                value: match reason {
                    Some(s) => cbor::text(s),
                    None => cbor::null(),
                },
            },
            MapEntry {
                key: cbor::text("disposition"),
                value: cbor::text(disposition.as_str()),
            },
            MapEntry {
                key: cbor::text("membership_hash"),
                value: cbor::bytes(membership_hash),
            },
        ];
        cbor::encode_map(&entries)
    }

    pub fn sign(
        side_key: &SideKey,
        verse: [u8; PUBLIC_KEY_LEN],
        membership_hash: [u8; 32],
        reason: Option<String>,
        disposition: DataDisposition,
    ) -> Result<Self> {
        let side = side_key.public_bytes();
        let unsigned = Self::encode_unsigned(
            &verse,
            &side,
            &membership_hash,
            reason.as_deref(),
            disposition,
        );
        let digest = blake3::hash(&unsigned);
        let signature = side_key.sign(digest.as_bytes());
        Ok(Self {
            verse,
            side,
            membership_hash,
            reason,
            disposition,
            signature,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let entries = [
            MapEntry {
                key: cbor::text("side"),
                value: cbor::bytes(&self.side),
            },
            MapEntry {
                key: cbor::text("verse"),
                value: cbor::bytes(&self.verse),
            },
            MapEntry {
                key: cbor::text("reason"),
                value: match &self.reason {
                    Some(s) => cbor::text(s),
                    None => cbor::null(),
                },
            },
            MapEntry {
                key: cbor::text("signature"),
                value: cbor::bytes(&self.signature),
            },
            MapEntry {
                key: cbor::text("disposition"),
                value: cbor::text(self.disposition.as_str()),
            },
            MapEntry {
                key: cbor::text("membership_hash"),
                value: cbor::bytes(&self.membership_hash),
            },
        ];
        cbor::encode_map(&entries)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = CborReader::new(bytes);
        let n = r.read_map_header()?;
        if n != 6 {
            return Err(Error::CborDecode(format!(
                "VerseLeave expected 6 keys, got {n}"
            )));
        }
        let expected = [
            "side",
            "verse",
            "reason",
            "signature",
            "disposition",
            "membership_hash",
        ];
        let mut side = None;
        let mut verse = None;
        let mut reason: Option<Option<String>> = None;
        let mut signature = None;
        let mut disposition = None;
        let mut membership_hash = None;
        for e in expected {
            let k = r.read_text()?;
            if k != e {
                return Err(Error::CborNotCanonical(
                    "VerseLeave keys not in canonical order",
                ));
            }
            match e {
                "side" => side = Some(read_fixed_pubkey(&mut r, "side")?),
                "verse" => verse = Some(read_fixed_pubkey(&mut r, "verse")?),
                "reason" => {
                    let peek = *r
                        .remaining()
                        .first()
                        .ok_or_else(|| Error::CborDecode("missing reason".into()))?;
                    reason = Some(if peek == 0xF6 {
                        r.read_bytes_or_null()?;
                        None
                    } else {
                        Some(r.read_text()?.to_owned())
                    });
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
                "disposition" => {
                    disposition = Some(DataDisposition::parse(r.read_text()?)?);
                }
                "membership_hash" => {
                    let b = r.read_bytes()?;
                    if b.len() != 32 {
                        return Err(Error::BadFieldLength {
                            field: "membership_hash",
                            expected: 32,
                            got: b.len(),
                        });
                    }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(b);
                    membership_hash = Some(arr);
                }
                _ => unreachable!(),
            }
        }
        let side = side.ok_or(Error::Invariant("missing side"))?;
        let verse = verse.ok_or(Error::Invariant("missing verse"))?;
        let reason = reason.ok_or(Error::Invariant("missing reason"))?;
        let signature = signature.ok_or(Error::Invariant("missing signature"))?;
        let disposition = disposition.ok_or(Error::Invariant("missing disposition"))?;
        let membership_hash = membership_hash.ok_or(Error::Invariant("missing membership_hash"))?;

        let unsigned = Self::encode_unsigned(
            &verse,
            &side,
            &membership_hash,
            reason.as_deref(),
            disposition,
        );
        let digest = blake3::hash(&unsigned);
        PublicKey::from_bytes(&side)?.verify(digest.as_bytes(), &signature)?;

        Ok(Self {
            verse,
            side,
            membership_hash,
            reason,
            disposition,
            signature,
        })
    }
}

// ============================================================================
// 0x56 VerseRemove (§8.8)
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerseRemovePayload {
    pub verse: [u8; PUBLIC_KEY_LEN],
    pub side: [u8; PUBLIC_KEY_LEN],
    pub reason: String,
    pub issued_by: [u8; PUBLIC_KEY_LEN],
    pub issued_at: u64,
    /// Signed by `issued_by` over BLAKE3(unsigned encoding).
    pub signature: [u8; SIGNATURE_LEN],
}

impl VerseRemovePayload {
    /// Canonical key order: side < verse < reason < issued_at < issued_by < signature.
    fn encode_unsigned(
        verse: &[u8; PUBLIC_KEY_LEN],
        side: &[u8; PUBLIC_KEY_LEN],
        reason: &str,
        issued_by: &[u8; PUBLIC_KEY_LEN],
        issued_at: u64,
    ) -> Vec<u8> {
        let entries = [
            MapEntry {
                key: cbor::text("side"),
                value: cbor::bytes(side),
            },
            MapEntry {
                key: cbor::text("verse"),
                value: cbor::bytes(verse),
            },
            MapEntry {
                key: cbor::text("reason"),
                value: cbor::text(reason),
            },
            MapEntry {
                key: cbor::text("issued_at"),
                value: cbor::uint(issued_at),
            },
            MapEntry {
                key: cbor::text("issued_by"),
                value: cbor::bytes(issued_by),
            },
        ];
        cbor::encode_map(&entries)
    }

    pub fn sign(
        moderator_key: &SideKey,
        verse: [u8; PUBLIC_KEY_LEN],
        side: [u8; PUBLIC_KEY_LEN],
        reason: impl Into<String>,
        issued_at: u64,
    ) -> Result<Self> {
        let issued_by = moderator_key.public_bytes();
        let reason = reason.into();
        let unsigned = Self::encode_unsigned(&verse, &side, &reason, &issued_by, issued_at);
        let digest = blake3::hash(&unsigned);
        let signature = moderator_key.sign(digest.as_bytes());
        Ok(Self {
            verse,
            side,
            reason,
            issued_by,
            issued_at,
            signature,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let entries = [
            MapEntry {
                key: cbor::text("side"),
                value: cbor::bytes(&self.side),
            },
            MapEntry {
                key: cbor::text("verse"),
                value: cbor::bytes(&self.verse),
            },
            MapEntry {
                key: cbor::text("reason"),
                value: cbor::text(&self.reason),
            },
            MapEntry {
                key: cbor::text("issued_at"),
                value: cbor::uint(self.issued_at),
            },
            MapEntry {
                key: cbor::text("issued_by"),
                value: cbor::bytes(&self.issued_by),
            },
            MapEntry {
                key: cbor::text("signature"),
                value: cbor::bytes(&self.signature),
            },
        ];
        cbor::encode_map(&entries)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = CborReader::new(bytes);
        let n = r.read_map_header()?;
        if n != 6 {
            return Err(Error::CborDecode(format!(
                "VerseRemove expected 6 keys, got {n}"
            )));
        }
        let expected = [
            "side",
            "verse",
            "reason",
            "issued_at",
            "issued_by",
            "signature",
        ];
        let mut side = None;
        let mut verse = None;
        let mut reason = None;
        let mut issued_at = None;
        let mut issued_by = None;
        let mut signature = None;
        for e in expected {
            let k = r.read_text()?;
            if k != e {
                return Err(Error::CborNotCanonical(
                    "VerseRemove keys not in canonical order",
                ));
            }
            match e {
                "side" => side = Some(read_fixed_pubkey(&mut r, "side")?),
                "verse" => verse = Some(read_fixed_pubkey(&mut r, "verse")?),
                "reason" => reason = Some(r.read_text()?.to_owned()),
                "issued_at" => issued_at = Some(r.read_u64()?),
                "issued_by" => issued_by = Some(read_fixed_pubkey(&mut r, "issued_by")?),
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
                _ => unreachable!(),
            }
        }
        let side = side.ok_or(Error::Invariant("missing side"))?;
        let verse = verse.ok_or(Error::Invariant("missing verse"))?;
        let reason = reason.ok_or(Error::Invariant("missing reason"))?;
        let issued_at = issued_at.ok_or(Error::Invariant("missing issued_at"))?;
        let issued_by = issued_by.ok_or(Error::Invariant("missing issued_by"))?;
        let signature = signature.ok_or(Error::Invariant("missing signature"))?;

        let unsigned = Self::encode_unsigned(&verse, &side, &reason, &issued_by, issued_at);
        let digest = blake3::hash(&unsigned);
        PublicKey::from_bytes(&issued_by)?.verify(digest.as_bytes(), &signature)?;

        Ok(Self {
            verse,
            side,
            reason,
            issued_by,
            issued_at,
            signature,
        })
    }
}

// ============================================================================
// 0x58 VerseAmend — verse pushes a new ContractObject to members
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerseAmendPayload {
    pub contract: ContractObject,
}

impl VerseAmendPayload {
    pub fn encode(&self) -> Vec<u8> {
        let entries = [MapEntry {
            key: cbor::text("contract"),
            value: self.contract.to_wire_bytes(),
        }];
        cbor::encode_map(&entries)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = CborReader::new(bytes);
        let n = r.read_map_header()?;
        if n != 1 {
            return Err(Error::CborDecode(format!(
                "VerseAmend expected 1 key, got {n}"
            )));
        }
        if r.read_text()? != "contract" {
            return Err(Error::CborNotCanonical("VerseAmend expects 'contract'"));
        }
        let start = r.position();
        let contract = ContractObject::from_wire_bytes(&bytes[start..])?;
        Ok(Self { contract })
    }
}

// ============================================================================
// 0x59 VerseReconsent — member acknowledges a new contract version
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerseReconsentPayload {
    pub contract_hash: [u8; 32],
    /// Signed by the consenting side over BLAKE3(unsigned encoding).
    pub signature: [u8; SIGNATURE_LEN],
}

impl VerseReconsentPayload {
    fn encode_unsigned(contract_hash: &[u8; 32]) -> Vec<u8> {
        let entries = [MapEntry {
            key: cbor::text("contract_hash"),
            value: cbor::bytes(contract_hash),
        }];
        cbor::encode_map(&entries)
    }

    pub fn sign(side_key: &SideKey, contract_hash: [u8; 32]) -> Result<Self> {
        let unsigned = Self::encode_unsigned(&contract_hash);
        let digest = blake3::hash(&unsigned);
        let signature = side_key.sign(digest.as_bytes());
        Ok(Self {
            contract_hash,
            signature,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        // Canonical: signature (0x69) < contract_hash (0x6d).
        let entries = [
            MapEntry {
                key: cbor::text("signature"),
                value: cbor::bytes(&self.signature),
            },
            MapEntry {
                key: cbor::text("contract_hash"),
                value: cbor::bytes(&self.contract_hash),
            },
        ];
        cbor::encode_map(&entries)
    }

    /// Decode + verify against the side that signed it. Callers pass the
    /// expected `side_pubkey` (typically the envelope's `from`).
    pub fn decode_and_verify(bytes: &[u8], side_pubkey: &[u8; PUBLIC_KEY_LEN]) -> Result<Self> {
        let mut r = CborReader::new(bytes);
        let n = r.read_map_header()?;
        if n != 2 {
            return Err(Error::CborDecode(format!(
                "VerseReconsent expected 2 keys, got {n}"
            )));
        }
        if r.read_text()? != "signature" {
            return Err(Error::CborNotCanonical("expected 'signature' first"));
        }
        let b = r.read_bytes()?;
        if b.len() != SIGNATURE_LEN {
            return Err(Error::BadFieldLength {
                field: "signature",
                expected: SIGNATURE_LEN,
                got: b.len(),
            });
        }
        let mut signature = [0u8; SIGNATURE_LEN];
        signature.copy_from_slice(b);
        if r.read_text()? != "contract_hash" {
            return Err(Error::CborNotCanonical("expected 'contract_hash' second"));
        }
        let b = r.read_bytes()?;
        if b.len() != 32 {
            return Err(Error::BadFieldLength {
                field: "contract_hash",
                expected: 32,
                got: b.len(),
            });
        }
        let mut contract_hash = [0u8; 32];
        contract_hash.copy_from_slice(b);

        let unsigned = Self::encode_unsigned(&contract_hash);
        let digest = blake3::hash(&unsigned);
        PublicKey::from_bytes(side_pubkey)?.verify(digest.as_bytes(), &signature)?;

        Ok(Self {
            contract_hash,
            signature,
        })
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn encode_field_values(fields: &FieldValues) -> Vec<u8> {
    let mut entries: Vec<MapEntry> = fields
        .iter()
        .map(|(k, v)| MapEntry {
            key: cbor::text(k.as_str()),
            value: cbor::text(v),
        })
        .collect();
    entries.sort_by(|a, b| a.key.cmp(&b.key));
    cbor::encode_map(&entries)
}

fn decode_field_values(r: &mut CborReader<'_>) -> Result<FieldValues> {
    let n = r.read_map_header()?;
    let mut out: FieldValues = BTreeMap::new();
    let mut last: Option<Vec<u8>> = None;
    for _ in 0..n {
        let kstart = r.position();
        let k = r.read_text()?.to_owned();
        let kbytes = r.buf[kstart..r.position()].to_vec();
        if let Some(prev) = &last
            && prev >= &kbytes
        {
            return Err(Error::CborNotCanonical(
                "field values keys not in canonical order",
            ));
        }
        last = Some(kbytes);
        let v = r.read_text()?.to_owned();
        out.insert(FieldKind::new(k), v);
    }
    Ok(out)
}

fn read_fixed_pubkey(r: &mut CborReader<'_>, field: &'static str) -> Result<[u8; PUBLIC_KEY_LEN]> {
    let b = r.read_bytes()?;
    if b.len() != PUBLIC_KEY_LEN {
        return Err(Error::BadFieldLength {
            field,
            expected: PUBLIC_KEY_LEN,
            got: b.len(),
        });
    }
    let mut arr = [0u8; PUBLIC_KEY_LEN];
    arr.copy_from_slice(b);
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::MasterKey;
    use crate::verse::{FieldKind, FieldSpec};

    fn deterministic_side(seed: u8, label: &str) -> SideKey {
        let m = MasterKey::from_seed(&[seed; 32]);
        m.derive_side(&label.into()).unwrap()
    }

    #[test]
    fn contract_fetch_roundtrip() {
        let p = ContractFetchPayload { version: Some(2) };
        let bytes = p.encode();
        let decoded = ContractFetchPayload::decode(&bytes).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn contract_fetch_no_version_roundtrip() {
        let p = ContractFetchPayload { version: None };
        let bytes = p.encode();
        let decoded = ContractFetchPayload::decode(&bytes).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn contract_deliver_roundtrip() {
        let verse = deterministic_side(0x42, "verse");
        let contract = ContractObject::sign(
            &verse,
            1,
            "Title",
            "Desc",
            vec![FieldSpec {
                kind: FieldKind::new(FieldKind::DISPLAY_NAME),
                label: "Name".into(),
                description: None,
                validator: None,
            }],
            vec![],
            vec![],
            vec![],
            vec![],
            1_700_000_000,
        )
        .unwrap();
        let p = ContractDeliverPayload { contract };
        let bytes = p.encode();
        let decoded = ContractDeliverPayload::decode(&bytes).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn join_request_signed_round_trip() {
        let side = deterministic_side(0x99, "applicant");
        let mut fields = BTreeMap::new();
        fields.insert(FieldKind::new(FieldKind::DISPLAY_NAME), "yasmine".into());
        fields.insert(FieldKind::new(FieldKind::PRONOUN), "she/her".into());
        let p = JoinRequestPayload::sign(&side, [0xAB; 32], fields).unwrap();
        let bytes = p.encode();
        let decoded = JoinRequestPayload::decode(&bytes).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn join_request_tampered_fails_verification() {
        let side = deterministic_side(0x99, "applicant");
        let p = JoinRequestPayload::sign(&side, [0xAB; 32], BTreeMap::new()).unwrap();
        let mut bytes = p.encode();
        // Flip a bit in the contract_hash region (at the end of the map).
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        assert!(JoinRequestPayload::decode(&bytes).is_err());
    }

    #[test]
    fn join_accept_roundtrip() {
        let p = JoinAcceptPayload {
            membership_token: vec![0x01, 0x02, 0x03],
            key_nonce: [0x77; 16],
            sealed_content_key: vec![0xAA; 48],
        };
        let bytes = p.encode();
        let decoded = JoinAcceptPayload::decode(&bytes).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn join_decline_roundtrip() {
        let p = JoinDeclinePayload {
            contract_hash: [0x33; 32],
            reason: "moderator-rejected".into(),
        };
        let bytes = p.encode();
        let decoded = JoinDeclinePayload::decode(&bytes).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn verse_post_roundtrip() {
        let p = VersePostPayload {
            nonce: [0x11; 12],
            ciphertext: vec![0x22; 64],
        };
        let bytes = p.encode();
        let decoded = VersePostPayload::decode(&bytes).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn verse_leave_signed_round_trip() {
        let side = deterministic_side(0x55, "member");
        let p = VerseLeavePayload::sign(
            &side,
            [0xAA; 32],
            [0xBB; 32],
            Some("not for me".into()),
            DataDisposition::Retract,
        )
        .unwrap();
        let bytes = p.encode();
        let decoded = VerseLeavePayload::decode(&bytes).unwrap();
        assert_eq!(decoded, p);
        assert_eq!(decoded.disposition, DataDisposition::Retract);
    }

    #[test]
    fn verse_leave_with_no_reason() {
        let side = deterministic_side(0x55, "member");
        let p =
            VerseLeavePayload::sign(&side, [0xAA; 32], [0xBB; 32], None, DataDisposition::Retain)
                .unwrap();
        let bytes = p.encode();
        let decoded = VerseLeavePayload::decode(&bytes).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn verse_leave_tampered_fails_verification() {
        let side = deterministic_side(0x55, "member");
        let p = VerseLeavePayload::sign(
            &side,
            [0xAA; 32],
            [0xBB; 32],
            Some("x".into()),
            DataDisposition::Transfer,
        )
        .unwrap();
        let mut bytes = p.encode();
        // Flip a bit in the membership_hash region (last segment of the map).
        let i = bytes.len() - 5;
        bytes[i] ^= 0x01;
        assert!(VerseLeavePayload::decode(&bytes).is_err());
    }

    #[test]
    fn verse_remove_signed_round_trip() {
        let moderator = deterministic_side(0x77, "verse");
        let p = VerseRemovePayload::sign(
            &moderator,
            [0xAA; 32],
            [0xCC; 32],
            "harassment",
            1_700_000_000,
        )
        .unwrap();
        let bytes = p.encode();
        let decoded = VerseRemovePayload::decode(&bytes).unwrap();
        assert_eq!(decoded, p);
        assert_eq!(decoded.issued_by, moderator.public_bytes());
    }

    #[test]
    fn verse_remove_wrong_signer_fails() {
        let moderator = deterministic_side(0x77, "verse");
        let mut p =
            VerseRemovePayload::sign(&moderator, [0xAA; 32], [0xCC; 32], "reason", 1).unwrap();
        // Replace issued_by with a different key — signature won't verify.
        p.issued_by = [0x00; 32];
        let bytes = p.encode();
        assert!(VerseRemovePayload::decode(&bytes).is_err());
    }

    #[test]
    fn verse_amend_round_trip() {
        let verse = deterministic_side(0x42, "verse");
        let contract = ContractObject::sign(
            &verse,
            2,
            "Book Club v2",
            "Now with pronouns required.",
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            1_700_000_500,
        )
        .unwrap();
        let p = VerseAmendPayload { contract };
        let bytes = p.encode();
        let decoded = VerseAmendPayload::decode(&bytes).unwrap();
        assert_eq!(decoded, p);
        assert_eq!(decoded.contract.version, 2);
    }

    #[test]
    fn verse_reconsent_signed_round_trip() {
        let side = deterministic_side(0x88, "member");
        let p = VerseReconsentPayload::sign(&side, [0xEE; 32]).unwrap();
        let bytes = p.encode();
        let decoded =
            VerseReconsentPayload::decode_and_verify(&bytes, &side.public_bytes()).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn verse_reconsent_wrong_signer_fails() {
        let side_a = deterministic_side(0x88, "member-a");
        let side_b = deterministic_side(0x99, "member-b");
        let p = VerseReconsentPayload::sign(&side_a, [0xEE; 32]).unwrap();
        let bytes = p.encode();
        // Try to verify against side_b's pubkey — must fail.
        assert!(VerseReconsentPayload::decode_and_verify(&bytes, &side_b.public_bytes()).is_err());
    }

    #[test]
    fn data_disposition_round_trips() {
        for d in [
            DataDisposition::Retain,
            DataDisposition::Retract,
            DataDisposition::Transfer,
        ] {
            assert_eq!(DataDisposition::parse(d.as_str()).unwrap(), d);
        }
        assert!(DataDisposition::parse("bogus").is_err());
    }
}
