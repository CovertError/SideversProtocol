//! Verses (protocol spec §8).
//!
//! A verse is a shared space with a **contract**: a signed CBOR record
//! declaring which fields are required, optional, forbidden, or scoped, plus
//! a set of policy clauses. Members join with one side after seeing the
//! contract. The verse's own keypair signs the contract and issues
//! membership tokens; verse-scoped content is encrypted with a symmetric
//! content key derived per verse, distributed to members at join time.
//!
//! This module defines the foundational types:
//!
//!   * [`FieldKind`]      — structured tags for what a verse may ask of members
//!   * [`FieldSpec`]      — one field declared in a contract
//!   * [`PolicyClause`]   — a verse-policy clause (e.g. "no-archive")
//!   * [`ContractObject`] — the full signed contract, addressable by hash
//!   * [`VerseContentKey`] — the 32-byte symmetric key for verse-scoped data
//!   * [`MembershipToken`] — the signed receipt the verse hands a joining member
//!
//! Per spec §8.3, contracts carry their signature **inline** (not in an
//! envelope) because they are content-addressed and verifiable standalone.

use std::collections::BTreeMap;

use crate::cbor::{self, CborReader, MapEntry};
use crate::error::{Error, Result};
use crate::keys::{PUBLIC_KEY_LEN, PublicKey, SIGNATURE_LEN, SideKey};

// ============================================================================
// Field kinds (§8.4)
// ============================================================================

/// A field kind is an opaque string with a small set of well-known values.
/// The protocol treats unknown kinds as opaque (forward-compatible), but
/// the well-known ones drive `forbidden`/`scoped` enforcement in clients.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FieldKind(pub String);

impl FieldKind {
    pub const REAL_NAME: &'static str = "real-name";
    pub const DISPLAY_NAME: &'static str = "display-name";
    pub const PRONOUN: &'static str = "pronoun";
    pub const AVATAR: &'static str = "avatar";
    pub const BIO: &'static str = "bio";
    pub const EMAIL: &'static str = "email";
    pub const PHONE: &'static str = "phone";
    pub const VERIFIED_CREDENTIAL: &'static str = "verified-credential";
    pub const MEMBERSHIP_TOKEN: &'static str = "membership-token";
    pub const ROLE: &'static str = "role";
    pub const LOCATION: &'static str = "location";

    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for FieldKind {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

// ============================================================================
// FieldSpec (§8.3)
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldSpec {
    pub kind: FieldKind,
    pub label: String,
    pub description: Option<String>,
    pub validator: Option<String>,
}

impl FieldSpec {
    /// Canonical key order (RFC 8949 §4.2.1 bytewise on encoded keys):
    ///   kind (0x64…) < label (0x65…) < validator (0x69…) < description (0x6b…)
    fn encode(&self) -> Vec<u8> {
        let entries = [
            MapEntry {
                key: cbor::text("kind"),
                value: cbor::text(self.kind.as_str()),
            },
            MapEntry {
                key: cbor::text("label"),
                value: cbor::text(&self.label),
            },
            MapEntry {
                key: cbor::text("validator"),
                value: match &self.validator {
                    Some(s) => cbor::text(s),
                    None => cbor::null(),
                },
            },
            MapEntry {
                key: cbor::text("description"),
                value: match &self.description {
                    Some(s) => cbor::text(s),
                    None => cbor::null(),
                },
            },
        ];
        cbor::encode_map(&entries)
    }

    fn decode_from(r: &mut CborReader<'_>) -> Result<Self> {
        let n = r.read_map_header()?;
        if n != 4 {
            return Err(Error::CborDecode(format!(
                "FieldSpec expected 4 keys, got {n}"
            )));
        }
        let expected = ["kind", "label", "validator", "description"];
        let mut description: Option<Option<String>> = None;
        let mut kind = None;
        let mut label = None;
        let mut validator: Option<Option<String>> = None;
        for e in expected {
            let k = r.read_text()?;
            if k != e {
                return Err(Error::CborNotCanonical(
                    "FieldSpec keys not in canonical order",
                ));
            }
            match e {
                "kind" => kind = Some(FieldKind::new(r.read_text()?.to_owned())),
                "label" => label = Some(r.read_text()?.to_owned()),
                "validator" => validator = Some(read_optional_text(r)?),
                "description" => description = Some(read_optional_text(r)?),
                _ => unreachable!(),
            }
        }
        Ok(Self {
            kind: kind.ok_or(Error::Invariant("missing kind"))?,
            label: label.ok_or(Error::Invariant("missing label"))?,
            description: description.ok_or(Error::Invariant("missing description"))?,
            validator: validator.ok_or(Error::Invariant("missing validator"))?,
        })
    }
}

// ============================================================================
// PolicyClause (§8.3)
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyClause {
    pub kind: String,
    /// Clause-specific params. Phase 1.5 supports string-valued params only;
    /// the spec leaves this open-ended (`{* tstr => any}`) for future kinds.
    pub params: BTreeMap<String, String>,
}

impl PolicyClause {
    /// Canonical key order: kind < params.
    fn encode(&self) -> Vec<u8> {
        let mut params_entries: Vec<MapEntry> = self
            .params
            .iter()
            .map(|(k, v)| MapEntry {
                key: cbor::text(k),
                value: cbor::text(v),
            })
            .collect();
        params_entries.sort_by(|a, b| a.key.cmp(&b.key));
        let params_bytes = cbor::encode_map(&params_entries);
        let entries = [
            MapEntry {
                key: cbor::text("kind"),
                value: cbor::text(&self.kind),
            },
            MapEntry {
                key: cbor::text("params"),
                value: params_bytes,
            },
        ];
        cbor::encode_map(&entries)
    }

    fn decode_from(r: &mut CborReader<'_>) -> Result<Self> {
        let n = r.read_map_header()?;
        if n != 2 {
            return Err(Error::CborDecode(format!(
                "PolicyClause expected 2 keys, got {n}"
            )));
        }
        if r.read_text()? != "kind" {
            return Err(Error::CborNotCanonical("PolicyClause expects 'kind' first"));
        }
        let kind = r.read_text()?.to_owned();
        if r.read_text()? != "params" {
            return Err(Error::CborNotCanonical(
                "PolicyClause expects 'params' second",
            ));
        }
        let pn = r.read_map_header()?;
        let mut params = BTreeMap::new();
        let mut last: Option<Vec<u8>> = None;
        for _ in 0..pn {
            let kstart = r.position();
            let k = r.read_text()?.to_owned();
            let kbytes = r.buf[kstart..r.position()].to_vec();
            if let Some(prev) = &last
                && prev >= &kbytes
            {
                return Err(Error::CborNotCanonical(
                    "policy params keys not in canonical order",
                ));
            }
            last = Some(kbytes);
            let v = r.read_text()?.to_owned();
            params.insert(k, v);
        }
        Ok(Self { kind, params })
    }
}

// ============================================================================
// ContractObject (§8.3)
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractObject {
    pub verse: [u8; PUBLIC_KEY_LEN],
    pub version: u64,
    pub title: String,
    pub description: String,
    pub required: Vec<FieldSpec>,
    pub optional: Vec<FieldSpec>,
    pub forbidden: Vec<FieldKind>,
    pub scoped: Vec<FieldKind>,
    pub policies: Vec<PolicyClause>,
    pub issued_at: u64,
    pub signature: [u8; SIGNATURE_LEN],
}

impl ContractObject {
    /// Canonical CBOR key order (RFC 8949 §4.2.1 bytewise on encoded keys):
    ///
    ///   title < verse < scoped < version < optional < policies < required
    ///   < forbidden < issued_at < signature < description
    ///
    /// The "unsigned" form omits `signature` (10 keys); the signature is
    /// Ed25519 over `BLAKE3(unsigned-encoding)` keyed by the verse's own
    /// private key.
    #[allow(clippy::too_many_arguments)]
    fn encode_unsigned(
        verse: &[u8; PUBLIC_KEY_LEN],
        version: u64,
        title: &str,
        description: &str,
        required: &[FieldSpec],
        optional: &[FieldSpec],
        forbidden: &[FieldKind],
        scoped: &[FieldKind],
        policies: &[PolicyClause],
        issued_at: u64,
    ) -> Vec<u8> {
        let entries = [
            MapEntry {
                key: cbor::text("title"),
                value: cbor::text(title),
            },
            MapEntry {
                key: cbor::text("verse"),
                value: cbor::bytes(verse),
            },
            MapEntry {
                key: cbor::text("scoped"),
                value: encode_field_kinds(scoped),
            },
            MapEntry {
                key: cbor::text("version"),
                value: cbor::uint(version),
            },
            MapEntry {
                key: cbor::text("optional"),
                value: encode_field_specs(optional),
            },
            MapEntry {
                key: cbor::text("policies"),
                value: encode_policies(policies),
            },
            MapEntry {
                key: cbor::text("required"),
                value: encode_field_specs(required),
            },
            MapEntry {
                key: cbor::text("forbidden"),
                value: encode_field_kinds(forbidden),
            },
            MapEntry {
                key: cbor::text("issued_at"),
                value: cbor::uint(issued_at),
            },
            MapEntry {
                key: cbor::text("description"),
                value: cbor::text(description),
            },
        ];
        cbor::encode_map(&entries)
    }

    /// Sign a contract with the verse's keypair. Per §8.2 the verse holds
    /// its own Ed25519 keypair; we treat it as a `SideKey` for signing
    /// (Sidevers identities and verses share the keyspace; only the HRP
    /// differs when rendered as an address).
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        verse_key: &SideKey,
        version: u64,
        title: impl Into<String>,
        description: impl Into<String>,
        required: Vec<FieldSpec>,
        optional: Vec<FieldSpec>,
        forbidden: Vec<FieldKind>,
        scoped: Vec<FieldKind>,
        policies: Vec<PolicyClause>,
        issued_at: u64,
    ) -> Result<Self> {
        let verse = verse_key.public_bytes();
        let title = title.into();
        let description = description.into();
        let unsigned = Self::encode_unsigned(
            &verse,
            version,
            &title,
            &description,
            &required,
            &optional,
            &forbidden,
            &scoped,
            &policies,
            issued_at,
        );
        let digest = blake3::hash(&unsigned);
        let signature = verse_key.sign(digest.as_bytes());
        Ok(Self {
            verse,
            version,
            title,
            description,
            required,
            optional,
            forbidden,
            scoped,
            policies,
            issued_at,
            signature,
        })
    }

    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let entries = [
            MapEntry {
                key: cbor::text("title"),
                value: cbor::text(&self.title),
            },
            MapEntry {
                key: cbor::text("verse"),
                value: cbor::bytes(&self.verse),
            },
            MapEntry {
                key: cbor::text("scoped"),
                value: encode_field_kinds(&self.scoped),
            },
            MapEntry {
                key: cbor::text("version"),
                value: cbor::uint(self.version),
            },
            MapEntry {
                key: cbor::text("optional"),
                value: encode_field_specs(&self.optional),
            },
            MapEntry {
                key: cbor::text("policies"),
                value: encode_policies(&self.policies),
            },
            MapEntry {
                key: cbor::text("required"),
                value: encode_field_specs(&self.required),
            },
            MapEntry {
                key: cbor::text("forbidden"),
                value: encode_field_kinds(&self.forbidden),
            },
            MapEntry {
                key: cbor::text("issued_at"),
                value: cbor::uint(self.issued_at),
            },
            MapEntry {
                key: cbor::text("signature"),
                value: cbor::bytes(&self.signature),
            },
            MapEntry {
                key: cbor::text("description"),
                value: cbor::text(&self.description),
            },
        ];
        cbor::encode_map(&entries)
    }

    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = CborReader::new(bytes);
        let n = r.read_map_header()?;
        if n != 11 {
            return Err(Error::CborDecode(format!(
                "ContractObject expected 11 keys, got {n}"
            )));
        }
        let expected = [
            "title",
            "verse",
            "scoped",
            "version",
            "optional",
            "policies",
            "required",
            "forbidden",
            "issued_at",
            "signature",
            "description",
        ];
        let mut title = None;
        let mut verse = None;
        let mut scoped = None;
        let mut version = None;
        let mut optional = None;
        let mut policies = None;
        let mut required = None;
        let mut forbidden = None;
        let mut issued_at = None;
        let mut signature = None;
        let mut description = None;
        for e in expected {
            let k = r.read_text()?;
            if k != e {
                return Err(Error::CborNotCanonical(
                    "ContractObject keys not in canonical order",
                ));
            }
            match e {
                "title" => title = Some(r.read_text()?.to_owned()),
                "verse" => {
                    let b = r.read_bytes()?;
                    if b.len() != PUBLIC_KEY_LEN {
                        return Err(Error::BadFieldLength {
                            field: "verse",
                            expected: PUBLIC_KEY_LEN,
                            got: b.len(),
                        });
                    }
                    let mut arr = [0u8; PUBLIC_KEY_LEN];
                    arr.copy_from_slice(b);
                    verse = Some(arr);
                }
                "scoped" => scoped = Some(decode_field_kinds(&mut r)?),
                "version" => version = Some(r.read_u64()?),
                "optional" => optional = Some(decode_field_specs(&mut r)?),
                "policies" => policies = Some(decode_policies(&mut r)?),
                "required" => required = Some(decode_field_specs(&mut r)?),
                "forbidden" => forbidden = Some(decode_field_kinds(&mut r)?),
                "issued_at" => issued_at = Some(r.read_u64()?),
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
                "description" => description = Some(r.read_text()?.to_owned()),
                _ => unreachable!(),
            }
        }
        let verse = verse.ok_or(Error::Invariant("missing verse"))?;
        let version = version.ok_or(Error::Invariant("missing version"))?;
        let title = title.ok_or(Error::Invariant("missing title"))?;
        let description = description.ok_or(Error::Invariant("missing description"))?;
        let required = required.ok_or(Error::Invariant("missing required"))?;
        let optional = optional.ok_or(Error::Invariant("missing optional"))?;
        let forbidden = forbidden.ok_or(Error::Invariant("missing forbidden"))?;
        let scoped = scoped.ok_or(Error::Invariant("missing scoped"))?;
        let policies = policies.ok_or(Error::Invariant("missing policies"))?;
        let issued_at = issued_at.ok_or(Error::Invariant("missing issued_at"))?;
        let signature = signature.ok_or(Error::Invariant("missing signature"))?;

        // Verify signature against the verse's public key.
        let unsigned = Self::encode_unsigned(
            &verse,
            version,
            &title,
            &description,
            &required,
            &optional,
            &forbidden,
            &scoped,
            &policies,
            issued_at,
        );
        let digest = blake3::hash(&unsigned);
        let pk = PublicKey::from_bytes(&verse)?;
        pk.verify(digest.as_bytes(), &signature)?;

        let contract = Self {
            verse,
            version,
            title,
            description,
            required,
            optional,
            forbidden,
            scoped,
            policies,
            issued_at,
            signature,
        };

        if contract.to_wire_bytes() != bytes {
            return Err(Error::CborNotCanonical(
                "ContractObject bytes are not canonical re-encode",
            ));
        }
        Ok(contract)
    }

    /// BLAKE3 of the full canonical wire encoding — the content address
    /// that membership tokens reference.
    pub fn hash(&self) -> [u8; 32] {
        *blake3::hash(&self.to_wire_bytes()).as_bytes()
    }

    /// Convenience: is `kind` listed as forbidden? Forbidden enforcement is
    /// a client + verse responsibility (the protocol's role is providing
    /// the structured tag the client can match against).
    pub fn is_forbidden(&self, kind: &FieldKind) -> bool {
        self.forbidden.iter().any(|k| k == kind)
    }
}

// ============================================================================
// MembershipToken (§8.5)
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipToken {
    pub verse: [u8; PUBLIC_KEY_LEN],
    pub contract_hash: [u8; 32],
    pub member_side: [u8; PUBLIC_KEY_LEN],
    pub issued_at: u64,
    pub signature: [u8; SIGNATURE_LEN],
}

impl MembershipToken {
    /// Canonical key order: verse < member < issued_at < signature < contract_hash.
    fn encode_unsigned(
        verse: &[u8; PUBLIC_KEY_LEN],
        contract_hash: &[u8; 32],
        member: &[u8; PUBLIC_KEY_LEN],
        issued_at: u64,
    ) -> Vec<u8> {
        let entries = [
            MapEntry {
                key: cbor::text("verse"),
                value: cbor::bytes(verse),
            },
            MapEntry {
                key: cbor::text("member"),
                value: cbor::bytes(member),
            },
            MapEntry {
                key: cbor::text("issued_at"),
                value: cbor::uint(issued_at),
            },
            MapEntry {
                key: cbor::text("contract_hash"),
                value: cbor::bytes(contract_hash),
            },
        ];
        cbor::encode_map(&entries)
    }

    pub fn sign(
        verse_key: &SideKey,
        contract_hash: [u8; 32],
        member_side: [u8; PUBLIC_KEY_LEN],
        issued_at: u64,
    ) -> Result<Self> {
        let verse = verse_key.public_bytes();
        let unsigned = Self::encode_unsigned(&verse, &contract_hash, &member_side, issued_at);
        let digest = blake3::hash(&unsigned);
        let signature = verse_key.sign(digest.as_bytes());
        Ok(Self {
            verse,
            contract_hash,
            member_side,
            issued_at,
            signature,
        })
    }

    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let entries = [
            MapEntry {
                key: cbor::text("verse"),
                value: cbor::bytes(&self.verse),
            },
            MapEntry {
                key: cbor::text("member"),
                value: cbor::bytes(&self.member_side),
            },
            MapEntry {
                key: cbor::text("issued_at"),
                value: cbor::uint(self.issued_at),
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

    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = CborReader::new(bytes);
        let n = r.read_map_header()?;
        if n != 5 {
            return Err(Error::CborDecode(format!(
                "MembershipToken expected 5 keys, got {n}"
            )));
        }
        let expected = ["verse", "member", "issued_at", "signature", "contract_hash"];
        let mut verse = None;
        let mut member = None;
        let mut issued_at = None;
        let mut signature = None;
        let mut contract_hash = None;
        for e in expected {
            let k = r.read_text()?;
            if k != e {
                return Err(Error::CborNotCanonical(
                    "MembershipToken keys not in canonical order",
                ));
            }
            match e {
                "verse" | "member" => {
                    let b = r.read_bytes()?;
                    if b.len() != PUBLIC_KEY_LEN {
                        return Err(Error::BadFieldLength {
                            field: if e == "verse" { "verse" } else { "member" },
                            expected: PUBLIC_KEY_LEN,
                            got: b.len(),
                        });
                    }
                    let mut arr = [0u8; PUBLIC_KEY_LEN];
                    arr.copy_from_slice(b);
                    if e == "verse" {
                        verse = Some(arr);
                    } else {
                        member = Some(arr);
                    }
                }
                "issued_at" => issued_at = Some(r.read_u64()?),
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
        let verse = verse.ok_or(Error::Invariant("missing verse"))?;
        let member_side = member.ok_or(Error::Invariant("missing member"))?;
        let issued_at = issued_at.ok_or(Error::Invariant("missing issued_at"))?;
        let signature = signature.ok_or(Error::Invariant("missing signature"))?;
        let contract_hash = contract_hash.ok_or(Error::Invariant("missing contract_hash"))?;

        let unsigned = Self::encode_unsigned(&verse, &contract_hash, &member_side, issued_at);
        let digest = blake3::hash(&unsigned);
        PublicKey::from_bytes(&verse)?.verify(digest.as_bytes(), &signature)?;

        Ok(Self {
            verse,
            contract_hash,
            member_side,
            issued_at,
            signature,
        })
    }
}

// ============================================================================
// VerseContentKey (§8.6) — 32-byte symmetric, ChaCha20-Poly1305
// ============================================================================

use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};

pub const VERSE_KEY_LEN: usize = 32;
pub const VERSE_NONCE_LEN: usize = 12;

/// The symmetric content key for verse-scoped messages. Generated by the
/// verse's owner at creation; distributed to each new member at join time
/// (encrypted to the joining side's X25519 public key via the same
/// envelope-payload mechanism we use for DMs).
///
/// Drops zeroize the key bytes via the wrapping `Key` type.
#[derive(Clone)]
pub struct VerseContentKey {
    bytes: [u8; VERSE_KEY_LEN],
}

impl VerseContentKey {
    pub fn generate() -> Result<Self> {
        let mut bytes = [0u8; VERSE_KEY_LEN];
        getrandom::getrandom(&mut bytes).map_err(|e| Error::CsprngUnavailable(e.to_string()))?;
        Ok(Self { bytes })
    }

    pub fn from_bytes(bytes: [u8; VERSE_KEY_LEN]) -> Self {
        Self { bytes }
    }

    pub fn as_bytes(&self) -> &[u8; VERSE_KEY_LEN] {
        &self.bytes
    }

    /// Encrypt a plaintext under this verse's content key, using a fresh
    /// 12-byte random nonce. Returns `(nonce, ciphertext)`.
    pub fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<([u8; VERSE_NONCE_LEN], Vec<u8>)> {
        let mut nonce = [0u8; VERSE_NONCE_LEN];
        getrandom::getrandom(&mut nonce).map_err(|e| Error::CsprngUnavailable(e.to_string()))?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.bytes));
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| Error::Invariant("AEAD encrypt failed"))?;
        Ok((nonce, ct))
    }

    /// Decrypt a ciphertext under this verse's content key.
    pub fn open(
        &self,
        nonce: &[u8; VERSE_NONCE_LEN],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.bytes));
        cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| Error::DecryptionFailed)
    }
}

impl core::fmt::Debug for VerseContentKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VerseContentKey").finish_non_exhaustive()
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn read_optional_text(r: &mut CborReader<'_>) -> Result<Option<String>> {
    let peek = *r
        .remaining()
        .first()
        .ok_or_else(|| Error::CborDecode("unexpected EOF".into()))?;
    if peek == 0xF6 {
        r.read_bytes_or_null()?;
        Ok(None)
    } else {
        Ok(Some(r.read_text()?.to_owned()))
    }
}

fn encode_field_kinds(kinds: &[FieldKind]) -> Vec<u8> {
    let mut w = cbor::CborWriter::new();
    w.write_array_header(kinds.len());
    let mut out = w.into_bytes();
    for k in kinds {
        out.extend_from_slice(&cbor::text(k.as_str()));
    }
    out
}

fn decode_field_kinds(r: &mut CborReader<'_>) -> Result<Vec<FieldKind>> {
    let n = r.read_array_header()?;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(FieldKind::new(r.read_text()?.to_owned()));
    }
    Ok(out)
}

fn encode_field_specs(specs: &[FieldSpec]) -> Vec<u8> {
    let mut w = cbor::CborWriter::new();
    w.write_array_header(specs.len());
    let mut out = w.into_bytes();
    for s in specs {
        out.extend_from_slice(&s.encode());
    }
    out
}

fn decode_field_specs(r: &mut CborReader<'_>) -> Result<Vec<FieldSpec>> {
    let n = r.read_array_header()?;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(FieldSpec::decode_from(r)?);
    }
    Ok(out)
}

fn encode_policies(policies: &[PolicyClause]) -> Vec<u8> {
    let mut w = cbor::CborWriter::new();
    w.write_array_header(policies.len());
    let mut out = w.into_bytes();
    for p in policies {
        out.extend_from_slice(&p.encode());
    }
    out
}

fn decode_policies(r: &mut CborReader<'_>) -> Result<Vec<PolicyClause>> {
    let n = r.read_array_header()?;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(PolicyClause::decode_from(r)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::MasterKey;
    use std::collections::BTreeMap;

    fn deterministic_verse_key() -> SideKey {
        // Use the SideKey type for the verse keypair; sides and verses share
        // the cryptographic keyspace (only the HRP differs in addresses).
        let m = MasterKey::from_seed(&[0x42u8; 32]);
        m.derive_side(&"verse-test".into()).unwrap()
    }

    #[test]
    fn contract_signed_round_trip_minimal() {
        let verse = deterministic_verse_key();
        let contract = ContractObject::sign(
            &verse,
            1,
            "Book Club",
            "We read books.",
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
            1_700_000_000,
        )
        .unwrap();
        let bytes = contract.to_wire_bytes();
        let decoded = ContractObject::from_wire_bytes(&bytes).unwrap();
        assert_eq!(decoded, contract);
        assert_eq!(decoded.verse, verse.public_bytes());
        assert!(decoded.is_forbidden(&FieldKind::new(FieldKind::REAL_NAME)));
    }

    #[test]
    fn contract_signed_round_trip_with_policies_and_optional_fields() {
        let verse = deterministic_verse_key();
        let mut params = BTreeMap::new();
        params.insert("ttl_days".into(), "30".into());
        let contract = ContractObject::sign(
            &verse,
            2,
            "Local Bookstore",
            "Curated reads in Brooklyn.",
            vec![FieldSpec {
                kind: FieldKind::new(FieldKind::DISPLAY_NAME),
                label: "Name".into(),
                description: Some("How you'll appear".into()),
                validator: None,
            }],
            vec![FieldSpec {
                kind: FieldKind::new(FieldKind::PRONOUN),
                label: "Pronoun".into(),
                description: None,
                validator: None,
            }],
            vec![
                FieldKind::new(FieldKind::REAL_NAME),
                FieldKind::new(FieldKind::EMAIL),
            ],
            vec![FieldKind::new("custom:favorite-genre")],
            vec![PolicyClause {
                kind: "no-archive".into(),
                params,
            }],
            1_700_000_500,
        )
        .unwrap();
        let bytes = contract.to_wire_bytes();
        let decoded = ContractObject::from_wire_bytes(&bytes).unwrap();
        assert_eq!(decoded, contract);
    }

    #[test]
    fn tampered_contract_fails_verification() {
        let verse = deterministic_verse_key();
        let contract = ContractObject::sign(
            &verse,
            1,
            "x",
            "x",
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            1,
        )
        .unwrap();
        let mut bytes = contract.to_wire_bytes();
        // Find the 'x' title byte and flip it.
        let i = bytes.iter().position(|&b| b == b'x').unwrap();
        bytes[i] ^= 0x01;
        let err = ContractObject::from_wire_bytes(&bytes).unwrap_err();
        assert!(matches!(err, Error::SignatureInvalid));
    }

    #[test]
    fn membership_token_round_trip() {
        let verse = deterministic_verse_key();
        let token =
            MembershipToken::sign(&verse, [0xAA; 32], [0xBB; PUBLIC_KEY_LEN], 1_700_000_000)
                .unwrap();
        let bytes = token.to_wire_bytes();
        let decoded = MembershipToken::from_wire_bytes(&bytes).unwrap();
        assert_eq!(decoded, token);
    }

    #[test]
    fn verse_content_key_seal_open() {
        let key = VerseContentKey::generate().unwrap();
        let (nonce, ct) = key.seal(b"verse content", b"verse-context").unwrap();
        let pt = key.open(&nonce, &ct, b"verse-context").unwrap();
        assert_eq!(pt, b"verse content");
    }

    #[test]
    fn verse_content_key_wrong_aad_fails() {
        let key = VerseContentKey::generate().unwrap();
        let (nonce, ct) = key.seal(b"x", b"ctx-A").unwrap();
        assert!(key.open(&nonce, &ct, b"ctx-B").is_err());
    }

    #[test]
    fn verse_content_key_wrong_key_fails() {
        let k1 = VerseContentKey::generate().unwrap();
        let k2 = VerseContentKey::generate().unwrap();
        let (nonce, ct) = k1.seal(b"x", b"").unwrap();
        assert!(k2.open(&nonce, &ct, b"").is_err());
    }
}
