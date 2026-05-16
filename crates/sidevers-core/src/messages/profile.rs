//! Profile payloads (protocol spec §7.3).
//!
//! A profile is what a side reveals about itself when asked. It's a signed
//! object, content-addressed, that can be cached, gossiped, or re-served
//! by storage nodes without an outer envelope — anyone holding the bytes
//! can verify them.
//!
//! Wire format (one CBOR map, nine entries, canonical key order — RFC
//! 8949 §4.2.1 bytewise lex on encoded keys):
//!
//!   bio          : tstr / nil
//!   name         : tstr / nil
//!   side         : bstr (32 bytes, Ed25519 public key)
//!   links        : [* tstr] / nil
//!   avatar       : bstr (32 bytes) / nil   (BLAKE3 hash of an avatar object)
//!   fields       : {* tstr => any} / nil   (extension map; values are
//!                                            CBOR-opaque to this module)
//!   signature    : bstr (64 bytes, Ed25519(side_priv, BLAKE3(unsigned)))
//!   updated_at   : uint (unix seconds; latest-timestamp-wins per §7.3)
//!   capabilities : [* tstr]                (sorted; §7.7 tokens)
//!
//! The signing key MUST be the side named by `side`; the digest is computed
//! over the canonical CBOR of the 8-entry unsigned sub-map (everything but
//! `signature`).
//!
//! Spec §7.7 defines six standard capability tokens:
//!   - "direct-message"   accept direct messages
//!   - "storage-host"     willing to host content for others
//!   - "verse-moderate"   willing to accept moderator role in verses
//!   - "gossip-relay"     willing to propagate public content
//!   - "discoverable"     appears in registry discovery / peer exchange
//!   - "indexable"        public content may be indexed by search
//!
//! Phase 1.5d enforces `direct-message` at the network layer; the other
//! five round-trip but are advisory until later phases wire them up.

use std::collections::{BTreeMap, BTreeSet};

use crate::cbor::{self, CborReader, CborWriter, MapEntry};
use crate::error::{Error, Result};
use crate::keys::{PUBLIC_KEY_LEN, PublicKey, SIGNATURE_LEN, SideKey};

/// Standard capability tokens defined in protocol spec §7.7.
pub mod capability {
    pub const DIRECT_MESSAGE: &str = "direct-message";
    pub const STORAGE_HOST: &str = "storage-host";
    pub const VERSE_MODERATE: &str = "verse-moderate";
    pub const GOSSIP_RELAY: &str = "gossip-relay";
    pub const DISCOVERABLE: &str = "discoverable";
    pub const INDEXABLE: &str = "indexable";
}

/// A signed profile object, ready to publish or verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfilePayload {
    pub side: [u8; PUBLIC_KEY_LEN],
    pub name: Option<String>,
    pub avatar: Option<[u8; 32]>,
    pub bio: Option<String>,
    pub links: Option<Vec<String>>,
    pub fields: Option<BTreeMap<String, Vec<u8>>>,
    pub capabilities: BTreeSet<String>,
    pub updated_at: u64,
    pub signature: [u8; SIGNATURE_LEN],
}

impl ProfilePayload {
    /// Build the canonical CBOR of the unsigned 8-entry sub-map. The
    /// signature is computed as Ed25519 over BLAKE3 of these bytes.
    #[allow(clippy::too_many_arguments)]
    fn encode_unsigned(
        side: &[u8; PUBLIC_KEY_LEN],
        name: Option<&str>,
        avatar: Option<&[u8; 32]>,
        bio: Option<&str>,
        links: Option<&[String]>,
        fields: Option<&BTreeMap<String, Vec<u8>>>,
        capabilities: &BTreeSet<String>,
        updated_at: u64,
    ) -> Vec<u8> {
        let entries = [
            MapEntry {
                key: cbor::key("bio"),
                value: match bio {
                    Some(s) => cbor::text(s),
                    None => cbor::null(),
                },
            },
            MapEntry {
                key: cbor::key("name"),
                value: match name {
                    Some(s) => cbor::text(s),
                    None => cbor::null(),
                },
            },
            MapEntry {
                key: cbor::key("side"),
                value: cbor::bytes(side),
            },
            MapEntry {
                key: cbor::key("links"),
                value: match links {
                    Some(l) => encode_text_array(l),
                    None => cbor::null(),
                },
            },
            MapEntry {
                key: cbor::key("avatar"),
                value: match avatar {
                    Some(h) => cbor::bytes(h),
                    None => cbor::null(),
                },
            },
            MapEntry {
                key: cbor::key("fields"),
                value: match fields {
                    Some(m) => encode_fields_submap(m),
                    None => cbor::null(),
                },
            },
            MapEntry {
                key: cbor::key("updated_at"),
                value: cbor::uint(updated_at),
            },
            MapEntry {
                key: cbor::key("capabilities"),
                value: encode_text_array_iter(capabilities.iter().map(String::as_str)),
            },
        ];
        cbor::encode_map(&entries)
    }

    /// Sign a fresh profile object. The signing key MUST be the side whose
    /// profile this is; the `side` field on the returned payload is set
    /// from `side.public_bytes()` so callers can't accidentally claim a
    /// pubkey they don't control.
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        side: &SideKey,
        name: Option<String>,
        avatar: Option<[u8; 32]>,
        bio: Option<String>,
        links: Option<Vec<String>>,
        fields: Option<BTreeMap<String, Vec<u8>>>,
        capabilities: BTreeSet<String>,
        updated_at: u64,
    ) -> Result<Self> {
        let pk = side.public_bytes();
        let unsigned = Self::encode_unsigned(
            &pk,
            name.as_deref(),
            avatar.as_ref(),
            bio.as_deref(),
            links.as_deref(),
            fields.as_ref(),
            &capabilities,
            updated_at,
        );
        let digest = blake3::hash(&unsigned);
        let signature = side.sign(digest.as_bytes());
        Ok(Self {
            side: pk,
            name,
            avatar,
            bio,
            links,
            fields,
            capabilities,
            updated_at,
            signature,
        })
    }

    /// Encode the full 9-entry signed profile for the wire.
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let entries = [
            MapEntry {
                key: cbor::key("bio"),
                value: match &self.bio {
                    Some(s) => cbor::text(s),
                    None => cbor::null(),
                },
            },
            MapEntry {
                key: cbor::key("name"),
                value: match &self.name {
                    Some(s) => cbor::text(s),
                    None => cbor::null(),
                },
            },
            MapEntry {
                key: cbor::key("side"),
                value: cbor::bytes(&self.side),
            },
            MapEntry {
                key: cbor::key("links"),
                value: match &self.links {
                    Some(l) => encode_text_array(l),
                    None => cbor::null(),
                },
            },
            MapEntry {
                key: cbor::key("avatar"),
                value: match &self.avatar {
                    Some(h) => cbor::bytes(h),
                    None => cbor::null(),
                },
            },
            MapEntry {
                key: cbor::key("fields"),
                value: match &self.fields {
                    Some(m) => encode_fields_submap(m),
                    None => cbor::null(),
                },
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
                key: cbor::key("capabilities"),
                value: encode_text_array_iter(self.capabilities.iter().map(String::as_str)),
            },
        ];
        cbor::encode_map(&entries)
    }

    /// BLAKE3 hash of the wire-canonical form. Acts as the profile's
    /// content address.
    pub fn hash(&self) -> [u8; 32] {
        *blake3::hash(&self.to_wire_bytes()).as_bytes()
    }

    /// Parse + verify a profile from wire bytes. Rejects on any of:
    /// non-canonical CBOR, wrong key order, malformed field, or invalid
    /// signature.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = CborReader::new(bytes);
        let n = r.read_map_header()?;
        if n != 9 {
            return Err(Error::CborDecode(format!(
                "Profile expected 9 keys, got {n}"
            )));
        }
        let expected = [
            "bio",
            "name",
            "side",
            "links",
            "avatar",
            "fields",
            "signature",
            "updated_at",
            "capabilities",
        ];
        let mut bio: Option<Option<String>> = None;
        let mut name: Option<Option<String>> = None;
        let mut side: Option<[u8; PUBLIC_KEY_LEN]> = None;
        let mut links: Option<Option<Vec<String>>> = None;
        let mut avatar: Option<Option<[u8; 32]>> = None;
        let mut fields: Option<Option<BTreeMap<String, Vec<u8>>>> = None;
        let mut signature: Option<[u8; SIGNATURE_LEN]> = None;
        let mut updated_at: Option<u64> = None;
        let mut capabilities: Option<BTreeSet<String>> = None;
        for key in expected {
            let k = r.read_text()?;
            if k != key {
                return Err(Error::CborNotCanonical(
                    "Profile keys not in canonical order",
                ));
            }
            match key {
                "bio" => bio = Some(read_optional_text(&mut r)?),
                "name" => name = Some(read_optional_text(&mut r)?),
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
                "links" => links = Some(read_optional_text_array(&mut r)?),
                "avatar" => avatar = Some(read_optional_32(&mut r, "avatar")?),
                "fields" => fields = Some(read_optional_fields_map(&mut r, bytes)?),
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
                "capabilities" => capabilities = Some(read_text_set(&mut r)?),
                _ => unreachable!(),
            }
        }
        if !r.at_end() {
            return Err(Error::CborDecode("trailing bytes after Profile".into()));
        }
        let bio = bio.ok_or(Error::Invariant("missing bio"))?;
        let name = name.ok_or(Error::Invariant("missing name"))?;
        let side = side.ok_or(Error::Invariant("missing side"))?;
        let links = links.ok_or(Error::Invariant("missing links"))?;
        let avatar = avatar.ok_or(Error::Invariant("missing avatar"))?;
        let fields = fields.ok_or(Error::Invariant("missing fields"))?;
        let signature = signature.ok_or(Error::Invariant("missing signature"))?;
        let updated_at = updated_at.ok_or(Error::Invariant("missing updated_at"))?;
        let capabilities = capabilities.ok_or(Error::Invariant("missing capabilities"))?;

        let unsigned = Self::encode_unsigned(
            &side,
            name.as_deref(),
            avatar.as_ref(),
            bio.as_deref(),
            links.as_deref(),
            fields.as_ref(),
            &capabilities,
            updated_at,
        );
        let digest = blake3::hash(&unsigned);
        PublicKey::from_bytes(&side)?.verify(digest.as_bytes(), &signature)?;

        let payload = Self {
            side,
            name,
            avatar,
            bio,
            links,
            fields,
            capabilities,
            updated_at,
            signature,
        };

        if payload.to_wire_bytes() != bytes {
            return Err(Error::CborNotCanonical(
                "Profile bytes are not canonical re-encode",
            ));
        }
        Ok(payload)
    }

    /// True iff this profile declares the given capability token.
    pub fn has_capability(&self, token: &str) -> bool {
        self.capabilities.contains(token)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn encode_text_array(items: &[String]) -> Vec<u8> {
    encode_text_array_iter(items.iter().map(String::as_str))
}

fn encode_text_array_iter<'a, I: Iterator<Item = &'a str>>(items: I) -> Vec<u8> {
    let collected: Vec<&str> = items.collect();
    let mut w = CborWriter::new();
    w.write_array_header(collected.len());
    for s in collected {
        w.write_text(s);
    }
    w.into_bytes()
}

fn encode_fields_submap(fields: &BTreeMap<String, Vec<u8>>) -> Vec<u8> {
    let mut entries: Vec<MapEntry> = fields
        .iter()
        .map(|(k, v)| MapEntry {
            key: cbor::key(k),
            value: v.clone(),
        })
        .collect();
    entries.sort_by(|a, b| a.key.cmp(&b.key));
    cbor::encode_map(&entries)
}

fn read_optional_text(r: &mut CborReader<'_>) -> Result<Option<String>> {
    let peek = *r
        .remaining()
        .first()
        .ok_or_else(|| Error::CborDecode("missing text-or-null".into()))?;
    if peek == 0xF6 {
        let _ = r.read_bytes_or_null()?;
        Ok(None)
    } else {
        Ok(Some(r.read_text()?.to_owned()))
    }
}

fn read_optional_32(r: &mut CborReader<'_>, field: &'static str) -> Result<Option<[u8; 32]>> {
    match r.read_bytes_or_null()? {
        None => Ok(None),
        Some(b) => {
            if b.len() != 32 {
                return Err(Error::BadFieldLength {
                    field,
                    expected: 32,
                    got: b.len(),
                });
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(b);
            Ok(Some(arr))
        }
    }
}

fn read_optional_text_array(r: &mut CborReader<'_>) -> Result<Option<Vec<String>>> {
    let peek = *r
        .remaining()
        .first()
        .ok_or_else(|| Error::CborDecode("missing array-or-null".into()))?;
    if peek == 0xF6 {
        let _ = r.read_bytes_or_null()?;
        return Ok(None);
    }
    let n = r.read_array_header()?;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(r.read_text()?.to_owned());
    }
    Ok(Some(out))
}

fn read_text_set(r: &mut CborReader<'_>) -> Result<BTreeSet<String>> {
    let n = r.read_array_header()?;
    let mut prev: Option<String> = None;
    let mut out = BTreeSet::new();
    for _ in 0..n {
        let s = r.read_text()?.to_owned();
        if let Some(p) = &prev {
            // Capabilities must be in canonical sorted order with no
            // duplicates — otherwise the canonical re-encode check at the
            // top level would catch it, but we surface the specific reason
            // here.
            if s.as_str() <= p.as_str() {
                return Err(Error::CborNotCanonical(
                    "capabilities array not sorted / has duplicates",
                ));
            }
        }
        prev = Some(s.clone());
        out.insert(s);
    }
    Ok(out)
}

fn read_optional_fields_map(
    r: &mut CborReader<'_>,
    outer_bytes: &[u8],
) -> Result<Option<BTreeMap<String, Vec<u8>>>> {
    let peek = *r
        .remaining()
        .first()
        .ok_or_else(|| Error::CborDecode("missing map-or-null".into()))?;
    if peek == 0xF6 {
        let _ = r.read_bytes_or_null()?;
        return Ok(None);
    }
    let n = r.read_map_header()?;
    let mut out = BTreeMap::new();
    let mut prev_key: Option<Vec<u8>> = None;
    for _ in 0..n {
        // Capture the key's encoded bytes so we can verify canonical order
        // (sorted by encoded-key bytewise lex per RFC 8949 §4.2.1).
        let key_start = r.position();
        let k = r.read_text()?.to_owned();
        let key_end = r.position();
        let key_bytes = outer_bytes[key_start..key_end].to_vec();
        if let Some(prev) = &prev_key {
            if key_bytes <= *prev {
                return Err(Error::CborNotCanonical(
                    "fields map not in canonical key order",
                ));
            }
        }
        prev_key = Some(key_bytes);

        let value_start = r.position();
        skip_value(r)?;
        let value_end = r.position();
        out.insert(k, outer_bytes[value_start..value_end].to_vec());
    }
    Ok(Some(out))
}

/// Advance the reader past one CBOR value (skipping its bytes). Supports
/// the major types we use for `any` values inside the fields sub-map.
fn skip_value(r: &mut CborReader<'_>) -> Result<()> {
    skip_value_inner(r, crate::cbor::MAX_CBOR_SKIP_DEPTH)
}

fn skip_value_inner(r: &mut CborReader<'_>, depth: u8) -> Result<()> {
    if depth == 0 {
        return Err(Error::CborDecode(
            "skip_value depth budget exhausted (deeply nested CBOR)".into(),
        ));
    }
    let first = *r
        .remaining()
        .first()
        .ok_or_else(|| Error::CborDecode("EOF in skip".into()))?;
    let major = first >> 5;
    match major {
        0 | 1 => {
            r.read_u64()?;
        }
        2 => {
            r.read_bytes()?;
        }
        3 => {
            r.read_text()?;
        }
        4 => {
            let n = r.read_array_header()?;
            for _ in 0..n {
                skip_value_inner(r, depth - 1)?;
            }
        }
        5 => {
            let n = r.read_map_header()?;
            for _ in 0..n {
                skip_value_inner(r, depth - 1)?;
                skip_value_inner(r, depth - 1)?;
            }
        }
        7 => {
            // Simple values (null/true/false). Single byte for the ones we use.
            r.read_bytes_or_null()?;
        }
        _ => return Err(Error::CborDecode(format!("unexpected major {major}"))),
    }
    Ok(())
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
    fn profile_minimal_round_trip() {
        let side = fixture_side(0x10);
        let mut caps = BTreeSet::new();
        caps.insert(capability::DIRECT_MESSAGE.to_owned());
        let p = ProfilePayload::sign(
            &side,
            None, // name
            None, // avatar
            None, // bio
            None, // links
            None, // fields
            caps,
            1_700_000_000,
        )
        .unwrap();
        let bytes = p.to_wire_bytes();
        let parsed = ProfilePayload::from_wire_bytes(&bytes).unwrap();
        assert_eq!(parsed, p);
        assert!(parsed.has_capability(capability::DIRECT_MESSAGE));
    }

    #[test]
    fn profile_fully_populated_round_trip() {
        let side = fixture_side(0x20);
        let mut caps = BTreeSet::new();
        caps.insert(capability::DIRECT_MESSAGE.to_owned());
        caps.insert(capability::STORAGE_HOST.to_owned());
        caps.insert(capability::GOSSIP_RELAY.to_owned());
        let mut fields = BTreeMap::new();
        fields.insert("pronouns".to_owned(), cbor::text("they/them"));
        fields.insert("favorite_color".to_owned(), cbor::text("teal"));
        let p = ProfilePayload::sign(
            &side,
            Some("Alice".to_owned()),
            Some([0x42u8; 32]),
            Some("ML engineer; coffee enthusiast".to_owned()),
            Some(vec![
                "https://example.com/alice".to_owned(),
                "mailto:alice@example.com".to_owned(),
            ]),
            Some(fields),
            caps,
            1_700_001_000,
        )
        .unwrap();
        let bytes = p.to_wire_bytes();
        let parsed = ProfilePayload::from_wire_bytes(&bytes).unwrap();
        assert_eq!(parsed, p);
        assert_eq!(parsed.name.as_deref(), Some("Alice"));
        assert_eq!(parsed.avatar, Some([0x42u8; 32]));
        assert_eq!(
            parsed.bio.as_deref(),
            Some("ML engineer; coffee enthusiast")
        );
        assert_eq!(parsed.links.as_ref().unwrap().len(), 2);
        assert_eq!(parsed.fields.as_ref().unwrap().len(), 2);
        assert!(parsed.has_capability(capability::STORAGE_HOST));
    }

    #[test]
    fn profile_empty_capabilities_round_trips() {
        let side = fixture_side(0x30);
        let p =
            ProfilePayload::sign(&side, None, None, None, None, None, BTreeSet::new(), 1).unwrap();
        let bytes = p.to_wire_bytes();
        let parsed = ProfilePayload::from_wire_bytes(&bytes).unwrap();
        assert_eq!(parsed, p);
        assert!(parsed.capabilities.is_empty());
    }

    #[test]
    fn tampered_profile_signature_fails() {
        let side = fixture_side(0x40);
        let mut caps = BTreeSet::new();
        caps.insert(capability::DIRECT_MESSAGE.to_owned());
        let mut p =
            ProfilePayload::sign(&side, Some("X".to_owned()), None, None, None, None, caps, 1)
                .unwrap();
        p.signature[0] ^= 0xFF;
        let bytes = p.to_wire_bytes();
        let err = ProfilePayload::from_wire_bytes(&bytes).unwrap_err();
        assert!(matches!(err, Error::SignatureInvalid));
    }

    #[test]
    fn profile_rejects_claimed_pubkey_mismatch() {
        // Construct a profile that names side A's pubkey but is signed by
        // side B. Verification fails.
        let real_signer = fixture_side(0xAB);
        let claimed_pk = fixture_side(0xCD).public_bytes();
        let mut caps = BTreeSet::new();
        caps.insert(capability::DIRECT_MESSAGE.to_owned());
        let unsigned =
            ProfilePayload::encode_unsigned(&claimed_pk, None, None, None, None, None, &caps, 42);
        let digest = blake3::hash(&unsigned);
        let forged_sig = real_signer.sign(digest.as_bytes());
        let payload = ProfilePayload {
            side: claimed_pk,
            name: None,
            avatar: None,
            bio: None,
            links: None,
            fields: None,
            capabilities: caps,
            updated_at: 42,
            signature: forged_sig,
        };
        let bytes = payload.to_wire_bytes();
        let err = ProfilePayload::from_wire_bytes(&bytes).unwrap_err();
        assert!(matches!(err, Error::SignatureInvalid));
    }

    #[test]
    fn hash_changes_when_field_changes() {
        let side = fixture_side(0x50);
        let mut caps = BTreeSet::new();
        caps.insert(capability::DIRECT_MESSAGE.to_owned());
        let p1 = ProfilePayload::sign(
            &side,
            Some("A".to_owned()),
            None,
            None,
            None,
            None,
            caps.clone(),
            100,
        )
        .unwrap();
        let p2 = ProfilePayload::sign(
            &side,
            Some("B".to_owned()),
            None,
            None,
            None,
            None,
            caps,
            100,
        )
        .unwrap();
        assert_ne!(p1.hash(), p2.hash());
    }
}
