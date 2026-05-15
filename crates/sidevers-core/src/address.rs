//! Network addresses (protocol spec §2.5).
//!
//! An address is a 32-byte Ed25519 public key encoded as bech32m (BIP-350)
//! with a human-readable prefix:
//!
//!   * `sv1q...`  — a side (a person, or any addressable identity)
//!   * `svv1q...` — a verse
//!
//! Both share the same key space cryptographically; the HRP only tells the
//! client what kind of thing it's pointing at before any network call.
//!
//! Spec rules enforced here:
//!   * Lowercase only on the wire (bech32m is case-sensitive in mixed input).
//!   * Checksum must match; encoder/decoder uses bech32m, NOT bech32.
//!   * Address body is 32 bytes; anything else is rejected.

use bech32::{Bech32m, Hrp};

use crate::error::{Error, Result};
use crate::keys::{PUBLIC_KEY_LEN, PublicKey};

const HRP_SIDE: &str = "sv";
const HRP_VERSE: &str = "svv";

/// What kind of entity an address points at. Cryptographically identical
/// (both are Ed25519 public keys); the HRP distinguishes display.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressKind {
    Side,
    Verse,
}

impl AddressKind {
    pub fn hrp_str(&self) -> &'static str {
        match self {
            AddressKind::Side => HRP_SIDE,
            AddressKind::Verse => HRP_VERSE,
        }
    }

    fn hrp(&self) -> Hrp {
        // Safe: HRPs are compile-time-known lowercase ASCII.
        Hrp::parse_unchecked(self.hrp_str())
    }
}

/// A wire address: 32-byte public key + a kind tag.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Address {
    kind: AddressKind,
    key: [u8; PUBLIC_KEY_LEN],
}

impl Address {
    pub fn new(kind: AddressKind, key: [u8; PUBLIC_KEY_LEN]) -> Self {
        Self { kind, key }
    }

    pub fn from_public_key(kind: AddressKind, pk: &PublicKey) -> Self {
        Self {
            kind,
            key: pk.to_bytes(),
        }
    }

    pub fn kind(&self) -> AddressKind {
        self.kind
    }

    pub fn key_bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.key
    }

    pub fn into_key_bytes(self) -> [u8; PUBLIC_KEY_LEN] {
        self.key
    }

    pub fn public_key(&self) -> Result<PublicKey> {
        PublicKey::from_bytes(&self.key)
    }

    /// Encode this address in canonical bech32m form (lowercase).
    ///
    /// Returns `None` only if the HRP or data length is out of bech32m's
    /// supported range. Neither can happen with our fixed HRPs and 32-byte
    /// keys, so callers can `.unwrap()` in tests; production code should
    /// use `Display` (`format!("{addr}")`) which calls this.
    pub fn encode(&self) -> String {
        // SAFETY-equivalent argument: HRP is "sv"/"svv" (<=3 chars), data
        // is 32 bytes — well within bech32m's bounds. Encoder never errors
        // for these inputs.
        #[allow(clippy::expect_used)]
        {
            bech32::encode::<Bech32m>(self.kind.hrp(), &self.key)
                .expect("encoding a 32-byte key under a fixed HRP cannot fail")
        }
    }

    /// Parse a bech32m-encoded address. Rejects:
    ///
    ///   * Mixed-case input. The bech32 spec allows mixed-case for
    ///     readability but considers it non-canonical for transport.
    ///   * Bech32 (non-`m`) checksums.
    ///   * Unknown HRPs.
    ///   * Body lengths other than 32 bytes.
    pub fn parse(s: &str) -> Result<Self> {
        // Reject mixed case explicitly so we have one canonical form.
        let has_upper = s.chars().any(|c| c.is_ascii_uppercase());
        let has_lower = s.chars().any(|c| c.is_ascii_lowercase());
        if has_upper && has_lower {
            return Err(Error::Address("mixed case not allowed".into()));
        }
        let canonical = s.to_lowercase();

        let (hrp, data) = bech32::decode(&canonical)
            .map_err(|e| Error::Address(format!("bech32 decode: {e}")))?;

        let kind = match hrp.as_str() {
            HRP_SIDE => AddressKind::Side,
            HRP_VERSE => AddressKind::Verse,
            other => return Err(Error::Address(format!("unknown HRP: {other}"))),
        };

        if data.len() != PUBLIC_KEY_LEN {
            return Err(Error::Address(format!(
                "expected {PUBLIC_KEY_LEN} bytes, got {}",
                data.len()
            )));
        }

        // Round-trip through Bech32m to enforce that the input used the
        // bech32m checksum (and not the older bech32 checksum). If a Bech32
        // string decoded successfully, its re-encoding under Bech32m will
        // produce a different (correct-bech32m) string.
        let reencoded = bech32::encode::<Bech32m>(hrp, &data)
            .map_err(|e| Error::Address(format!("re-encode failed: {e}")))?;
        if reencoded != canonical {
            return Err(Error::Address(
                "non-canonical encoding (not bech32m)".into(),
            ));
        }

        let mut key = [0u8; PUBLIC_KEY_LEN];
        key.copy_from_slice(&data);
        Ok(Self { kind, key })
    }
}

impl core::fmt::Display for Address {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.encode())
    }
}

impl core::fmt::Debug for Address {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Address({})", self.encode())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::MasterKey;

    #[test]
    fn round_trip_side_address() {
        let master = MasterKey::generate().unwrap();
        let side = master.derive_side(&"work".into()).unwrap();
        let addr = Address::from_public_key(AddressKind::Side, &side.public());

        let encoded = addr.encode();
        assert!(encoded.starts_with("sv1"), "got {encoded}");
        assert!(!encoded.chars().any(|c| c.is_ascii_uppercase()));

        let decoded = Address::parse(&encoded).unwrap();
        assert_eq!(decoded, addr);
        assert_eq!(decoded.kind(), AddressKind::Side);
    }

    #[test]
    fn round_trip_verse_address() {
        let key = [9u8; PUBLIC_KEY_LEN];
        let addr = Address::new(AddressKind::Verse, key);
        let encoded = addr.encode();
        assert!(encoded.starts_with("svv1"), "got {encoded}");
        let decoded = Address::parse(&encoded).unwrap();
        assert_eq!(decoded.kind(), AddressKind::Verse);
        assert_eq!(decoded.key_bytes(), &key);
    }

    #[test]
    fn rejects_mixed_case() {
        let addr = Address::new(AddressKind::Side, [1u8; PUBLIC_KEY_LEN]);
        let mut s = addr.encode();
        // Flip one letter to uppercase.
        s.replace_range(3..4, &s[3..4].to_uppercase());
        assert!(Address::parse(&s).is_err());
    }

    #[test]
    fn rejects_corrupted_checksum() {
        let addr = Address::new(AddressKind::Side, [1u8; PUBLIC_KEY_LEN]);
        let mut s = addr.encode();
        // Mutate the last character (part of the checksum).
        let last = s.pop().unwrap();
        let replacement = if last == 'q' { 'p' } else { 'q' };
        s.push(replacement);
        assert!(Address::parse(&s).is_err());
    }

    #[test]
    fn different_kinds_with_same_key_are_different_addresses() {
        let key = [42u8; PUBLIC_KEY_LEN];
        let side = Address::new(AddressKind::Side, key);
        let verse = Address::new(AddressKind::Verse, key);
        assert_ne!(side.encode(), verse.encode());
    }
}
