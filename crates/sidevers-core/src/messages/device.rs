//! Multi-device co-holder wire types (protocol spec §7.5).
//!
//! A side can run on multiple devices (phone + laptop + hosted node) by
//! adding co-holders. The wire flow:
//!
//!   1. **Existing device** generates a 16-byte pairing nonce, records it
//!      locally, and shows a QR code (`PairingQr::encode`) that the user
//!      points the new device's camera at.
//!   2. **New device** scans the QR (`PairingQr::parse`), generates a
//!      fresh ephemeral device Ed25519 + X25519 keypair, dials the QR's
//!      listed address with `Intent::Direct`, sends `PairingRequestPayload`
//!      signed by its device key.
//!   3. **Existing device** verifies the request's signature + the
//!      nonce-match, builds the inner state bundle (side seed + profile +
//!      relationships + retired_sides + lifecycle + co_holders), seals
//!      it via X25519+ChaCha20-Poly1305 to the new device's X25519
//!      pubkey, and sends `StateBundlePayload` (signed by the SIDE's
//!      keypair) back on the same bidi stream.
//!   4. **New device** verifies the bundle's binding (recipient, nonce,
//!      AEAD tag, side-seed-matches-side-pubkey), installs the side
//!      state, and persists it locally.
//!
//! Removal: any co-holder can publish a `DeviceRevokePayload` (signed by
//! the side's keypair) — remaining co-holders mark the removed device
//! as revoked. Network-level enforcement of revocation is out of scope
//! while the side's keypair is shared (Phase 1.5g).
//!
//! Wire format follows the same canonical-CBOR + BLAKE3-digest + Ed25519
//! pattern as `LinkageProof` and `ContractObject`: every payload is a
//! map with a `signature` field, the digest is `BLAKE3(unsigned-map)`,
//! signatures are verified on decode, and a re-encode check rejects
//! non-canonical input.

use crate::cbor::{self, CborReader, CborWriter, MapEntry};
use crate::error::{Error, Result};
use crate::keys::{PUBLIC_KEY_LEN, PublicKey, SIGNATURE_LEN, SideKey};

/// Pairing nonce length: 16 bytes from the CSPRNG. Encoded into the QR;
/// confirmed by the existing device on PairingRequest receipt.
pub const PAIRING_NONCE_LEN: usize = 16;

/// Sealing nonce length matching the protocol envelope nonce
/// (`sidevers_core::envelope::NONCE_LEN`). `core_payload::seal` accepts a
/// 16-byte envelope-style nonce and derives the 12-byte AEAD nonce
/// internally.
pub const KEY_NONCE_LEN: usize = crate::envelope::NONCE_LEN;

/// AAD bound to the sealed state bundle. Prevents bundle ciphertext from
/// being mis-decrypted in another context.
pub const STATE_BUNDLE_AAD: &[u8] = b"sidevers/v1/device-state-bundle";

// =========================================================================
// PairingRequestPayload (0x26: new device → existing device)
// =========================================================================

/// Sent by the new device to the existing device on a Direct-intent
/// connection. Carries the side being joined, the new device's keys, and
/// the QR-shared nonce. Signed by the new device's Ed25519 key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingRequestPayload {
    /// Side address (Ed25519 pubkey) the new device wants to join.
    pub side: [u8; 32],
    /// New device's Ed25519 pubkey (signer of this request).
    pub device_pubkey: [u8; 32],
    /// New device's X25519 pubkey (recipient of the sealed bundle).
    pub device_x25519_pubkey: [u8; 32],
    /// The one-time pairing nonce from the QR.
    pub nonce: [u8; PAIRING_NONCE_LEN],
    /// Ed25519 signature over `BLAKE3(unsigned)` by `device_pubkey`.
    pub signature: [u8; SIGNATURE_LEN],
}

impl PairingRequestPayload {
    /// Canonical key order (byte-lex on encoded keys):
    /// `nonce` (5) < `side` (5) < `signature` (10) < `device_pubkey` (14)
    /// < `device_x25519_pubkey` (21). NB: nonce 0x65 < side 0x64 means
    /// side comes first. Let me recompute: "nonce" len=5 → 0x65, "side"
    /// len=4 → 0x64. side < nonce. Recomputed: side < nonce <
    /// signature < device_pubkey < device_x25519_pubkey.
    fn encode_unsigned(
        side: &[u8; 32],
        device_pubkey: &[u8; PUBLIC_KEY_LEN],
        device_x25519_pubkey: &[u8; 32],
        nonce: &[u8; PAIRING_NONCE_LEN],
    ) -> Vec<u8> {
        let entries = [
            MapEntry {
                key: cbor::key("side"),
                value: cbor::bytes(side),
            },
            MapEntry {
                key: cbor::key("nonce"),
                value: cbor::bytes(nonce),
            },
            MapEntry {
                key: cbor::key("device_pubkey"),
                value: cbor::bytes(device_pubkey),
            },
            MapEntry {
                key: cbor::key("device_x25519_pubkey"),
                value: cbor::bytes(device_x25519_pubkey),
            },
        ];
        cbor::encode_map(&entries)
    }

    /// Sign a request. `device_signing_key` is the new device's Ed25519
    /// secret (typically a freshly-generated ephemeral key).
    pub fn sign(
        side: [u8; 32],
        device_signing_key: &SideKey,
        device_x25519_pubkey: [u8; 32],
        nonce: [u8; PAIRING_NONCE_LEN],
    ) -> Result<Self> {
        let device_pubkey = device_signing_key.public_bytes();
        let unsigned = Self::encode_unsigned(&side, &device_pubkey, &device_x25519_pubkey, &nonce);
        let digest = blake3::hash(&unsigned);
        let signature = device_signing_key.sign(digest.as_bytes());
        Ok(Self {
            side,
            device_pubkey,
            device_x25519_pubkey,
            nonce,
            signature,
        })
    }

    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let entries = [
            MapEntry {
                key: cbor::key("side"),
                value: cbor::bytes(&self.side),
            },
            MapEntry {
                key: cbor::key("nonce"),
                value: cbor::bytes(&self.nonce),
            },
            MapEntry {
                key: cbor::key("signature"),
                value: cbor::bytes(&self.signature),
            },
            MapEntry {
                key: cbor::key("device_pubkey"),
                value: cbor::bytes(&self.device_pubkey),
            },
            MapEntry {
                key: cbor::key("device_x25519_pubkey"),
                value: cbor::bytes(&self.device_x25519_pubkey),
            },
        ];
        cbor::encode_map(&entries)
    }

    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = CborReader::new(bytes);
        let n = r.read_map_header()?;
        if n != 5 {
            return Err(Error::CborDecode(format!(
                "PairingRequest expected 5 keys, got {n}"
            )));
        }
        let expected = [
            "side",
            "nonce",
            "signature",
            "device_pubkey",
            "device_x25519_pubkey",
        ];
        let mut side: Option<[u8; 32]> = None;
        let mut nonce: Option<[u8; PAIRING_NONCE_LEN]> = None;
        let mut signature: Option<[u8; SIGNATURE_LEN]> = None;
        let mut device_pubkey: Option<[u8; PUBLIC_KEY_LEN]> = None;
        let mut device_x25519_pubkey: Option<[u8; 32]> = None;
        for k in expected {
            let got = r.read_text()?;
            if got != k {
                return Err(Error::CborNotCanonical(
                    "PairingRequest keys not in canonical order",
                ));
            }
            match k {
                "side" => side = Some(read_32(&mut r, "side")?),
                "nonce" => {
                    let b = r.read_bytes()?;
                    if b.len() != PAIRING_NONCE_LEN {
                        return Err(Error::BadFieldLength {
                            field: "nonce",
                            expected: PAIRING_NONCE_LEN,
                            got: b.len(),
                        });
                    }
                    let mut a = [0u8; PAIRING_NONCE_LEN];
                    a.copy_from_slice(b);
                    nonce = Some(a);
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
                    let mut a = [0u8; SIGNATURE_LEN];
                    a.copy_from_slice(b);
                    signature = Some(a);
                }
                "device_pubkey" => device_pubkey = Some(read_32(&mut r, "device_pubkey")?),
                "device_x25519_pubkey" => {
                    device_x25519_pubkey = Some(read_32(&mut r, "device_x25519_pubkey")?)
                }
                _ => unreachable!(),
            }
        }
        if !r.at_end() {
            return Err(Error::CborDecode(
                "trailing bytes after PairingRequest".into(),
            ));
        }
        let side = side.ok_or(Error::Invariant("missing side"))?;
        let device_pubkey = device_pubkey.ok_or(Error::Invariant("missing device_pubkey"))?;
        let device_x25519_pubkey =
            device_x25519_pubkey.ok_or(Error::Invariant("missing device_x25519_pubkey"))?;
        let nonce = nonce.ok_or(Error::Invariant("missing nonce"))?;
        let signature = signature.ok_or(Error::Invariant("missing signature"))?;

        // Verify the signature against the new device's pubkey.
        let unsigned = Self::encode_unsigned(&side, &device_pubkey, &device_x25519_pubkey, &nonce);
        let digest = blake3::hash(&unsigned);
        PublicKey::from_bytes(&device_pubkey)?.verify(digest.as_bytes(), &signature)?;

        let p = Self {
            side,
            device_pubkey,
            device_x25519_pubkey,
            nonce,
            signature,
        };
        if p.to_wire_bytes() != bytes {
            return Err(Error::CborNotCanonical(
                "PairingRequest bytes are not canonical re-encode",
            ));
        }
        Ok(p)
    }
}

// =========================================================================
// StateBundlePayload (0x27: existing device → new device, sealed)
// =========================================================================

/// The encrypted-and-signed state bundle: outer envelope-style fields
/// plus the sealed ciphertext. `sealed_state` is opened with
/// `core_payload::open(sealed_state, recipient_x25519_secret, signing_side,
/// key_nonce, STATE_BUNDLE_AAD)` to recover the inner CBOR map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateBundlePayload {
    pub side: [u8; 32],
    pub recipient_device: [u8; 32],
    pub nonce: [u8; PAIRING_NONCE_LEN],
    pub key_nonce: [u8; KEY_NONCE_LEN],
    pub sealed_state: Vec<u8>,
    pub signature: [u8; SIGNATURE_LEN],
}

impl StateBundlePayload {
    fn encode_unsigned(
        side: &[u8; 32],
        recipient_device: &[u8; 32],
        nonce: &[u8; PAIRING_NONCE_LEN],
        key_nonce: &[u8; KEY_NONCE_LEN],
        sealed_state: &[u8],
    ) -> Vec<u8> {
        // Canonical order by encoded-key bytes:
        // "side" (5b) < "nonce" (6b)... actually let me compute.
        // side → 0x64 73 69 64 65 (5 bytes)
        // nonce → 0x65 6e 6f 6e 63 65 (6 bytes)
        // key_nonce → 0x69 6b 65 79 5f 6e 6f 6e 63 65 (10 bytes)
        // sealed_state → 0x6c 73 65 61 6c 65 64 5f 73 74 61 74 65 (13)
        // recipient_device → 0x70 72 65 63 ... (17 bytes)
        // signature → 0x69 73 69 ... (10 bytes, but 0x69 < 0x6c so signature < sealed_state)
        // Final order (unsigned): side, nonce, key_nonce, sealed_state, recipient_device
        let entries = [
            MapEntry {
                key: cbor::key("side"),
                value: cbor::bytes(side),
            },
            MapEntry {
                key: cbor::key("nonce"),
                value: cbor::bytes(nonce),
            },
            MapEntry {
                key: cbor::key("key_nonce"),
                value: cbor::bytes(key_nonce),
            },
            MapEntry {
                key: cbor::key("sealed_state"),
                value: cbor::bytes(sealed_state),
            },
            MapEntry {
                key: cbor::key("recipient_device"),
                value: cbor::bytes(recipient_device),
            },
        ];
        cbor::encode_map(&entries)
    }

    /// Sign a state bundle with the SIDE's keypair (any current
    /// co-holder of the side may produce one — they all hold the same key).
    pub fn sign(
        side_key: &SideKey,
        recipient_device: [u8; 32],
        nonce: [u8; PAIRING_NONCE_LEN],
        key_nonce: [u8; KEY_NONCE_LEN],
        sealed_state: Vec<u8>,
    ) -> Result<Self> {
        let side = side_key.public_bytes();
        let unsigned =
            Self::encode_unsigned(&side, &recipient_device, &nonce, &key_nonce, &sealed_state);
        let digest = blake3::hash(&unsigned);
        let signature = side_key.sign(digest.as_bytes());
        Ok(Self {
            side,
            recipient_device,
            nonce,
            key_nonce,
            sealed_state,
            signature,
        })
    }

    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let entries = [
            MapEntry {
                key: cbor::key("side"),
                value: cbor::bytes(&self.side),
            },
            MapEntry {
                key: cbor::key("nonce"),
                value: cbor::bytes(&self.nonce),
            },
            MapEntry {
                key: cbor::key("key_nonce"),
                value: cbor::bytes(&self.key_nonce),
            },
            MapEntry {
                key: cbor::key("signature"),
                value: cbor::bytes(&self.signature),
            },
            MapEntry {
                key: cbor::key("sealed_state"),
                value: cbor::bytes(&self.sealed_state),
            },
            MapEntry {
                key: cbor::key("recipient_device"),
                value: cbor::bytes(&self.recipient_device),
            },
        ];
        cbor::encode_map(&entries)
    }

    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = CborReader::new(bytes);
        let n = r.read_map_header()?;
        if n != 6 {
            return Err(Error::CborDecode(format!(
                "StateBundle expected 6 keys, got {n}"
            )));
        }
        let expected = [
            "side",
            "nonce",
            "key_nonce",
            "signature",
            "sealed_state",
            "recipient_device",
        ];
        let mut side: Option<[u8; 32]> = None;
        let mut nonce: Option<[u8; PAIRING_NONCE_LEN]> = None;
        let mut key_nonce: Option<[u8; KEY_NONCE_LEN]> = None;
        let mut signature: Option<[u8; SIGNATURE_LEN]> = None;
        let mut sealed_state: Option<Vec<u8>> = None;
        let mut recipient_device: Option<[u8; 32]> = None;
        for k in expected {
            let got = r.read_text()?;
            if got != k {
                return Err(Error::CborNotCanonical(
                    "StateBundle keys not in canonical order",
                ));
            }
            match k {
                "side" => side = Some(read_32(&mut r, "side")?),
                "nonce" => {
                    let b = r.read_bytes()?;
                    if b.len() != PAIRING_NONCE_LEN {
                        return Err(Error::BadFieldLength {
                            field: "nonce",
                            expected: PAIRING_NONCE_LEN,
                            got: b.len(),
                        });
                    }
                    let mut a = [0u8; PAIRING_NONCE_LEN];
                    a.copy_from_slice(b);
                    nonce = Some(a);
                }
                "key_nonce" => {
                    let b = r.read_bytes()?;
                    if b.len() != KEY_NONCE_LEN {
                        return Err(Error::BadFieldLength {
                            field: "key_nonce",
                            expected: KEY_NONCE_LEN,
                            got: b.len(),
                        });
                    }
                    let mut a = [0u8; KEY_NONCE_LEN];
                    a.copy_from_slice(b);
                    key_nonce = Some(a);
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
                    let mut a = [0u8; SIGNATURE_LEN];
                    a.copy_from_slice(b);
                    signature = Some(a);
                }
                "sealed_state" => sealed_state = Some(r.read_bytes()?.to_vec()),
                "recipient_device" => recipient_device = Some(read_32(&mut r, "recipient_device")?),
                _ => unreachable!(),
            }
        }
        if !r.at_end() {
            return Err(Error::CborDecode("trailing bytes after StateBundle".into()));
        }
        let side = side.ok_or(Error::Invariant("missing side"))?;
        let recipient_device =
            recipient_device.ok_or(Error::Invariant("missing recipient_device"))?;
        let nonce = nonce.ok_or(Error::Invariant("missing nonce"))?;
        let key_nonce = key_nonce.ok_or(Error::Invariant("missing key_nonce"))?;
        let sealed_state = sealed_state.ok_or(Error::Invariant("missing sealed_state"))?;
        let signature = signature.ok_or(Error::Invariant("missing signature"))?;

        let unsigned =
            Self::encode_unsigned(&side, &recipient_device, &nonce, &key_nonce, &sealed_state);
        let digest = blake3::hash(&unsigned);
        PublicKey::from_bytes(&side)?.verify(digest.as_bytes(), &signature)?;

        let p = Self {
            side,
            recipient_device,
            nonce,
            key_nonce,
            sealed_state,
            signature,
        };
        if p.to_wire_bytes() != bytes {
            return Err(Error::CborNotCanonical(
                "StateBundle bytes are not canonical re-encode",
            ));
        }
        Ok(p)
    }
}

// =========================================================================
// DeviceRevokePayload (0x28: any co-holder → network, signed by side)
// =========================================================================

/// Published by any current co-holder to revoke another device from the
/// side's co-holder set. Signed by the side's keypair (which every
/// co-holder holds, by §7.5's "equally privileged" model).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRevokePayload {
    pub side: [u8; 32],
    pub device_pubkey: [u8; 32],
    pub revoked_at: u64,
    pub reason: Option<String>,
    pub signature: [u8; SIGNATURE_LEN],
}

impl DeviceRevokePayload {
    fn encode_unsigned(
        side: &[u8; 32],
        device_pubkey: &[u8; 32],
        revoked_at: u64,
        reason: Option<&str>,
    ) -> Vec<u8> {
        // side (5) < reason (7) < revoked_at (11) < device_pubkey (14)
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
                key: cbor::key("revoked_at"),
                value: cbor::uint(revoked_at),
            },
            MapEntry {
                key: cbor::key("device_pubkey"),
                value: cbor::bytes(device_pubkey),
            },
        ];
        cbor::encode_map(&entries)
    }

    pub fn sign(
        side_key: &SideKey,
        device_pubkey: [u8; 32],
        revoked_at: u64,
        reason: Option<String>,
    ) -> Result<Self> {
        let side = side_key.public_bytes();
        let unsigned = Self::encode_unsigned(&side, &device_pubkey, revoked_at, reason.as_deref());
        let digest = blake3::hash(&unsigned);
        let signature = side_key.sign(digest.as_bytes());
        Ok(Self {
            side,
            device_pubkey,
            revoked_at,
            reason,
            signature,
        })
    }

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
                key: cbor::key("revoked_at"),
                value: cbor::uint(self.revoked_at),
            },
            MapEntry {
                key: cbor::key("device_pubkey"),
                value: cbor::bytes(&self.device_pubkey),
            },
        ];
        cbor::encode_map(&entries)
    }

    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = CborReader::new(bytes);
        let n = r.read_map_header()?;
        if n != 5 {
            return Err(Error::CborDecode(format!(
                "DeviceRevoke expected 5 keys, got {n}"
            )));
        }
        let expected = ["side", "reason", "signature", "revoked_at", "device_pubkey"];
        let mut side: Option<[u8; 32]> = None;
        let mut reason: Option<Option<String>> = None;
        let mut signature: Option<[u8; SIGNATURE_LEN]> = None;
        let mut revoked_at: Option<u64> = None;
        let mut device_pubkey: Option<[u8; 32]> = None;
        for k in expected {
            let got = r.read_text()?;
            if got != k {
                return Err(Error::CborNotCanonical(
                    "DeviceRevoke keys not in canonical order",
                ));
            }
            match k {
                "side" => side = Some(read_32(&mut r, "side")?),
                "reason" => {
                    let peek = *r
                        .remaining()
                        .first()
                        .ok_or_else(|| Error::CborDecode("missing reason".into()))?;
                    if peek == 0xF6 {
                        let _ = r.read_bytes_or_null()?;
                        reason = Some(None);
                    } else {
                        reason = Some(Some(r.read_text()?.to_owned()));
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
                    let mut a = [0u8; SIGNATURE_LEN];
                    a.copy_from_slice(b);
                    signature = Some(a);
                }
                "revoked_at" => revoked_at = Some(r.read_u64()?),
                "device_pubkey" => device_pubkey = Some(read_32(&mut r, "device_pubkey")?),
                _ => unreachable!(),
            }
        }
        if !r.at_end() {
            return Err(Error::CborDecode(
                "trailing bytes after DeviceRevoke".into(),
            ));
        }
        let side = side.ok_or(Error::Invariant("missing side"))?;
        let reason = reason.ok_or(Error::Invariant("missing reason"))?;
        let signature = signature.ok_or(Error::Invariant("missing signature"))?;
        let revoked_at = revoked_at.ok_or(Error::Invariant("missing revoked_at"))?;
        let device_pubkey = device_pubkey.ok_or(Error::Invariant("missing device_pubkey"))?;

        let unsigned = Self::encode_unsigned(&side, &device_pubkey, revoked_at, reason.as_deref());
        let digest = blake3::hash(&unsigned);
        PublicKey::from_bytes(&side)?.verify(digest.as_bytes(), &signature)?;

        let p = Self {
            side,
            device_pubkey,
            revoked_at,
            reason,
            signature,
        };
        if p.to_wire_bytes() != bytes {
            return Err(Error::CborNotCanonical(
                "DeviceRevoke bytes are not canonical re-encode",
            ));
        }
        Ok(p)
    }
}

// =========================================================================
// ContactCard — "share me as a friend" QR (Phase 3 Stage C)
// =========================================================================
//
// Distinct from PairingQr in three ways:
//   * No nonce. ContactCard carries only PUBLIC information; no
//     handshake state to bind to.
//   * No side seed. The receiver becomes a *contact*, not a co-holder.
//     Adding a contact requires zero private-key material from the
//     publisher.
//   * Different URI scheme (`sidevers-contact:1:` vs `sidevers-pair:1:`)
//     so a frontend paste/scan auto-routes to the right handler and a
//     contact-card paste can never accidentally trigger a pairing
//     handshake.
//
// Wire layout (after base32 decode):
//   1B  version (0x01)
//   32B side public key
//   2B  display_name length (u16 BE)   — UTF-8 string, 0..=512 bytes
//   N   display_name bytes
//   2B  side_label length (u16 BE)     — UTF-8 string, 0..=64 bytes
//   N   side_label bytes
//   2B  dial_addr length (u16 BE)      — UTF-8 string, 1..=256 bytes
//   N   dial_addr bytes

/// QR-encoded "add me as a friend" code. URI scheme
/// `sidevers-contact:1:<base32>` (lowercase, no padding). Carries
/// the side's public address, an optional display name + side label
/// for UI hints, and the network address to dial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactCard {
    /// Side public key (Ed25519, 32 bytes).
    pub side: [u8; 32],
    /// Network address the friend's client should dial. UTF-8.
    pub dial_addr: String,
    /// Optional display name to show on first encounter. The receiver
    /// is free to override locally; never wire-validated.
    pub display_name: Option<String>,
    /// Optional side label (e.g. "work", "private") — gives the
    /// recipient a hint about which context this is.
    pub side_label: Option<String>,
}

const CONTACT_QR_VERSION: u8 = 0x01;
const CONTACT_QR_SCHEME_PREFIX: &str = "sidevers-contact:1:";
const CONTACT_DISPLAY_NAME_MAX: usize = 512;
const CONTACT_SIDE_LABEL_MAX: usize = 64;
const CONTACT_DIAL_ADDR_MAX: usize = 256;

impl ContactCard {
    /// Encode to URI form.
    pub fn encode(&self) -> String {
        let dn = self.display_name.as_deref().unwrap_or("");
        let sl = self.side_label.as_deref().unwrap_or("");
        let da = self.dial_addr.as_str();
        let mut buf = Vec::with_capacity(1 + 32 + 2 + dn.len() + 2 + sl.len() + 2 + da.len());
        buf.push(CONTACT_QR_VERSION);
        buf.extend_from_slice(&self.side);
        buf.extend_from_slice(&(dn.len() as u16).to_be_bytes());
        buf.extend_from_slice(dn.as_bytes());
        buf.extend_from_slice(&(sl.len() as u16).to_be_bytes());
        buf.extend_from_slice(sl.as_bytes());
        buf.extend_from_slice(&(da.len() as u16).to_be_bytes());
        buf.extend_from_slice(da.as_bytes());
        let b32 = base32_encode(&buf);
        format!("{CONTACT_QR_SCHEME_PREFIX}{b32}")
    }

    /// Parse from URI form. Rejects truncated, oversized, or non-UTF-8
    /// fields. A successful parse means the payload was well-formed —
    /// it says nothing about whether the side is one the caller wants
    /// to befriend; that's a UI-level confirmation.
    pub fn parse(s: &str) -> Result<Self> {
        let rest = s
            .strip_prefix(CONTACT_QR_SCHEME_PREFIX)
            .ok_or_else(|| Error::CborDecode("contact QR: missing scheme prefix".into()))?;
        let bytes = base32_decode(rest)
            .ok_or_else(|| Error::CborDecode("contact QR: bad base32".into()))?;
        if bytes.is_empty() || bytes[0] != CONTACT_QR_VERSION {
            return Err(Error::CborDecode("contact QR: bad version".into()));
        }
        // 1 (version) + 32 (side) + 2 + 2 + 2 (three length prefixes) = 39
        if bytes.len() < 1 + 32 + 6 {
            return Err(Error::CborDecode("contact QR: truncated".into()));
        }
        let mut side = [0u8; 32];
        side.copy_from_slice(&bytes[1..33]);

        let mut pos = 33usize;
        let (display_name, new_pos) = read_lp_string(
            &bytes,
            pos,
            CONTACT_DISPLAY_NAME_MAX,
            "contact QR: display_name",
        )?;
        pos = new_pos;
        let (side_label, new_pos) = read_lp_string(
            &bytes,
            pos,
            CONTACT_SIDE_LABEL_MAX,
            "contact QR: side_label",
        )?;
        pos = new_pos;
        let (dial_addr, new_pos) =
            read_lp_string(&bytes, pos, CONTACT_DIAL_ADDR_MAX, "contact QR: dial_addr")?;
        if dial_addr.is_empty() {
            return Err(Error::CborDecode("contact QR: empty dial_addr".into()));
        }
        if new_pos != bytes.len() {
            return Err(Error::CborDecode("contact QR: trailing bytes".into()));
        }
        Ok(Self {
            side,
            dial_addr,
            display_name: if display_name.is_empty() {
                None
            } else {
                Some(display_name)
            },
            side_label: if side_label.is_empty() {
                None
            } else {
                Some(side_label)
            },
        })
    }
}

/// Read a length-prefixed (u16-BE) UTF-8 string starting at `pos`.
/// Returns the parsed string and the position after the field. Rejects
/// runs over `max_len` or off the end of the buffer.
fn read_lp_string(
    bytes: &[u8],
    pos: usize,
    max_len: usize,
    field: &'static str,
) -> Result<(String, usize)> {
    if pos + 2 > bytes.len() {
        return Err(Error::CborDecode(format!("{field}: missing length")));
    }
    let len = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
    let start = pos + 2;
    let end = start + len;
    if end > bytes.len() {
        return Err(Error::CborDecode(format!("{field}: truncated body")));
    }
    if len > max_len {
        return Err(Error::CborDecode(format!("{field}: oversized")));
    }
    let s = core::str::from_utf8(&bytes[start..end])
        .map_err(|_| Error::CborDecode(format!("{field}: not utf-8")))?
        .to_owned();
    Ok((s, end))
}

// =========================================================================
// PairingQr — URI codec for the QR code the existing device shows
// =========================================================================

/// QR-encoded pairing handshake. URI scheme `sidevers-pair:1:<base32>`
/// (lowercase, no padding). Carries the side address, one-time nonce,
/// and the dial address of the existing device's per-side endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingQr {
    pub side: [u8; 32],
    pub nonce: [u8; PAIRING_NONCE_LEN],
    /// Network address the new device should dial. UTF-8; up to ~256 chars.
    pub dial_addr: String,
}

/// Version byte for the v1 QR encoding.
const QR_VERSION: u8 = 0x01;
const QR_SCHEME_PREFIX: &str = "sidevers-pair:1:";

impl PairingQr {
    /// Encode to URI form.
    pub fn encode(&self) -> String {
        let mut buf = Vec::with_capacity(1 + 32 + PAIRING_NONCE_LEN + 2 + self.dial_addr.len());
        buf.push(QR_VERSION);
        buf.extend_from_slice(&self.side);
        buf.extend_from_slice(&self.nonce);
        let addr = self.dial_addr.as_bytes();
        buf.extend_from_slice(&(addr.len() as u16).to_be_bytes());
        buf.extend_from_slice(addr);
        let b32 = base32_encode(&buf);
        format!("{QR_SCHEME_PREFIX}{b32}")
    }

    /// Parse from URI form.
    pub fn parse(s: &str) -> Result<Self> {
        let rest = s
            .strip_prefix(QR_SCHEME_PREFIX)
            .ok_or_else(|| Error::CborDecode("pairing QR: missing scheme prefix".into()))?;
        let bytes = base32_decode(rest)
            .ok_or_else(|| Error::CborDecode("pairing QR: bad base32".into()))?;
        if bytes.is_empty() || bytes[0] != QR_VERSION {
            return Err(Error::CborDecode("pairing QR: bad version".into()));
        }
        if bytes.len() < 1 + 32 + PAIRING_NONCE_LEN + 2 {
            return Err(Error::CborDecode("pairing QR: truncated".into()));
        }
        let mut side = [0u8; 32];
        side.copy_from_slice(&bytes[1..33]);
        let mut nonce = [0u8; PAIRING_NONCE_LEN];
        nonce.copy_from_slice(&bytes[33..33 + PAIRING_NONCE_LEN]);
        let len_pos = 33 + PAIRING_NONCE_LEN;
        let addr_len = u16::from_be_bytes([bytes[len_pos], bytes[len_pos + 1]]) as usize;
        let addr_start = len_pos + 2;
        if bytes.len() != addr_start + addr_len {
            return Err(Error::CborDecode("pairing QR: addr length mismatch".into()));
        }
        let dial_addr = core::str::from_utf8(&bytes[addr_start..])
            .map_err(|_| Error::CborDecode("pairing QR: addr not utf-8".into()))?
            .to_owned();
        Ok(Self {
            side,
            nonce,
            dial_addr,
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn read_32(r: &mut CborReader<'_>, field: &'static str) -> Result<[u8; 32]> {
    let b = r.read_bytes()?;
    if b.len() != 32 {
        return Err(Error::BadFieldLength {
            field,
            expected: 32,
            got: b.len(),
        });
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(b);
    Ok(a)
}

// RFC 4648 base32 (lowercase, no padding) — simple inline impl to avoid
// adding a base32 crate dep.
const BASE32_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

fn base32_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity((input.len() * 8).div_ceil(5));
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &b in input {
        buffer = (buffer << 8) | (b as u32);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1F) as usize;
            out.push(BASE32_ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1F) as usize;
        out.push(BASE32_ALPHABET[idx] as char);
    }
    out
}

fn base32_decode(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 5 / 8);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for c in input.chars() {
        let idx = BASE32_ALPHABET.iter().position(|&x| x as char == c)? as u32;
        buffer = (buffer << 5) | idx;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1u32 << bits) - 1;
        }
    }
    Some(out)
}

// =========================================================================
// State bundle inner CBOR map — sealed_state plaintext layout
// =========================================================================

/// Plaintext fields packed into the sealed state bundle. Encoded via
/// `encode` to CBOR before sealing; decoded via `decode` after unsealing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateBundleInner {
    pub side_seed: [u8; 32],
    pub profile_wire: Option<Vec<u8>>, // ProfilePayload::to_wire_bytes()
    pub relationships: Vec<RelationshipRecord>,
    pub retired_sides: Vec<[u8; 32]>, // sorted
    pub lifecycle: String,            // "Created" / "Active" / "Dormant" / "Retired"
    pub co_holders: Vec<[u8; 32]>,    // sorted
    pub bundled_at: u64,
}

/// CBOR-friendly mirror of `sidevers_net::relationships::SideRelationship`
/// — kept here so sidevers-core can encode/decode it without depending on
/// sidevers-net.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelationshipRecord {
    pub address: [u8; 32],
    pub nickname: Option<String>,
    pub introduced_by: Option<[u8; 32]>,
    pub capabilities: Vec<String>, // sorted
    pub notes: Option<String>,
    pub pinned: bool,
    pub added_at: u64,
}

impl StateBundleInner {
    /// Encode the inner bundle as canonical CBOR. Sealing happens at the
    /// outer (StateBundlePayload) layer.
    pub fn encode(&self) -> Vec<u8> {
        // Canonical key order over: bundled_at, lifecycle, profile,
        // co_holders, retired_sides, side_seed, relationships.
        // Computed: bundled_at(11), lifecycle(10), profile(8), side_seed(10), co_holders(11),
        // retired_sides(14), relationships(14).
        // By byte-lex on encoded keys:
        //   profile (0x67 70 ...) 8 bytes
        //   side_seed (0x69 73 69 64 65 5f 73 65 65 64) 10 bytes
        //   lifecycle (0x69 6c 69 ...) 10 bytes
        //   bundled_at (0x6a 62 75 ...) 11 bytes
        //   co_holders (0x6a 63 6f ...) 11 bytes
        //   relationships (0x6d 72 65 ...) 14 bytes
        //   retired_sides (0x6d 72 65 74 69 ...) 14 bytes
        // Within 10: 'l' (0x6c) < 's' (0x73), so lifecycle key bytes 0x69 0x6c ... vs side_seed 0x69 0x73 ...
        // → lifecycle < side_seed.
        // Within 11: 'b' (0x62) < 'c' (0x63), so bundled_at < co_holders.
        // Within 14: relationships starts 0x6d 0x72 0x65 0x6c (l), retired_sides 0x6d 0x72 0x65 0x74 (t).
        // 'l' (0x6c) < 't' (0x74), so relationships < retired_sides.
        // Final: profile < lifecycle < side_seed < bundled_at < co_holders < relationships < retired_sides
        let entries = [
            MapEntry {
                key: cbor::key("profile"),
                value: match &self.profile_wire {
                    Some(b) => cbor::bytes(b),
                    None => cbor::null(),
                },
            },
            MapEntry {
                key: cbor::key("lifecycle"),
                value: cbor::text(&self.lifecycle),
            },
            MapEntry {
                key: cbor::key("side_seed"),
                value: cbor::bytes(&self.side_seed),
            },
            MapEntry {
                key: cbor::key("bundled_at"),
                value: cbor::uint(self.bundled_at),
            },
            MapEntry {
                key: cbor::key("co_holders"),
                value: encode_bytes_array(&self.co_holders),
            },
            MapEntry {
                key: cbor::key("relationships"),
                value: encode_relationship_array(&self.relationships),
            },
            MapEntry {
                key: cbor::key("retired_sides"),
                value: encode_bytes_array(&self.retired_sides),
            },
        ];
        cbor::encode_map(&entries)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = CborReader::new(bytes);
        let n = r.read_map_header()?;
        if n != 7 {
            return Err(Error::CborDecode(format!(
                "StateBundleInner expected 7 keys, got {n}"
            )));
        }
        let expected = [
            "profile",
            "lifecycle",
            "side_seed",
            "bundled_at",
            "co_holders",
            "relationships",
            "retired_sides",
        ];
        let mut profile_wire: Option<Option<Vec<u8>>> = None;
        let mut lifecycle: Option<String> = None;
        let mut side_seed: Option<[u8; 32]> = None;
        let mut bundled_at: Option<u64> = None;
        let mut co_holders: Option<Vec<[u8; 32]>> = None;
        let mut relationships: Option<Vec<RelationshipRecord>> = None;
        let mut retired_sides: Option<Vec<[u8; 32]>> = None;

        for k in expected {
            let got = r.read_text()?;
            if got != k {
                return Err(Error::CborNotCanonical(
                    "StateBundleInner keys not in canonical order",
                ));
            }
            match k {
                "profile" => {
                    let peek = *r
                        .remaining()
                        .first()
                        .ok_or_else(|| Error::CborDecode("missing profile".into()))?;
                    if peek == 0xF6 {
                        let _ = r.read_bytes_or_null()?;
                        profile_wire = Some(None);
                    } else {
                        profile_wire = Some(Some(r.read_bytes()?.to_vec()));
                    }
                }
                "lifecycle" => lifecycle = Some(r.read_text()?.to_owned()),
                "side_seed" => side_seed = Some(read_32(&mut r, "side_seed")?),
                "bundled_at" => bundled_at = Some(r.read_u64()?),
                "co_holders" => co_holders = Some(decode_bytes_array(&mut r)?),
                "relationships" => relationships = Some(decode_relationship_array(&mut r, bytes)?),
                "retired_sides" => retired_sides = Some(decode_bytes_array(&mut r)?),
                _ => unreachable!(),
            }
        }
        if !r.at_end() {
            return Err(Error::CborDecode(
                "trailing bytes after StateBundleInner".into(),
            ));
        }
        Ok(StateBundleInner {
            side_seed: side_seed.ok_or(Error::Invariant("missing side_seed"))?,
            profile_wire: profile_wire.ok_or(Error::Invariant("missing profile"))?,
            relationships: relationships.ok_or(Error::Invariant("missing relationships"))?,
            retired_sides: retired_sides.ok_or(Error::Invariant("missing retired_sides"))?,
            lifecycle: lifecycle.ok_or(Error::Invariant("missing lifecycle"))?,
            co_holders: co_holders.ok_or(Error::Invariant("missing co_holders"))?,
            bundled_at: bundled_at.ok_or(Error::Invariant("missing bundled_at"))?,
        })
    }
}

fn encode_bytes_array(items: &[[u8; 32]]) -> Vec<u8> {
    let mut w = CborWriter::new();
    w.write_array_header(items.len());
    for b in items {
        w.write_bytes(b);
    }
    w.into_bytes()
}

fn decode_bytes_array(r: &mut CborReader<'_>) -> Result<Vec<[u8; 32]>> {
    let n = r.read_array_header()?;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(read_32(r, "bytes array item")?);
    }
    Ok(out)
}

fn encode_relationship_array(items: &[RelationshipRecord]) -> Vec<u8> {
    let mut w = CborWriter::new();
    w.write_array_header(items.len());
    for rec in items {
        // Canonical order: bio? no — record fields are different. Compute:
        //   address(8), pinned(7), notes(6), nickname(9), added_at(9),
        //   capabilities(13), introduced_by(14).
        // Wait — they're text keys not byte arrays. Let me compute encoded
        // key lengths and order:
        //   "added_at" → 9 bytes (1+8)
        //   "address" → 8 bytes (1+7)
        //   "capabilities" → 13 bytes (1+12)
        //   "introduced_by" → 14 bytes (1+13)
        //   "nickname" → 9 bytes (1+8)
        //   "notes" → 6 bytes (1+5)
        //   "pinned" → 7 bytes (1+6)
        // By byte-lex on encoded keys:
        //   notes (0x65 6e 6f 74 65 73) — 6 bytes
        //   pinned (0x66 70 ...) — 7 bytes
        //   address (0x67 61 64 ...) — 8 bytes
        //   added_at (0x68 61 64 ...) — 9 bytes (0x68 because length 8 → 0x60+8)
        //   nickname (0x68 6e 69 ...) — 9 bytes (0x68 same length; tie broken by 'a' < 'n' so added_at < nickname)
        //   capabilities (0x6c ...) — 13 bytes (0x60+12)
        //   introduced_by (0x6d ...) — 14 bytes (0x60+13)
        // Final order: notes, pinned, address, added_at, nickname, capabilities, introduced_by
        let entries = [
            MapEntry {
                key: cbor::key("notes"),
                value: match &rec.notes {
                    Some(s) => cbor::text(s),
                    None => cbor::null(),
                },
            },
            MapEntry {
                key: cbor::key("pinned"),
                value: cbor::boolean(rec.pinned),
            },
            MapEntry {
                key: cbor::key("address"),
                value: cbor::bytes(&rec.address),
            },
            MapEntry {
                key: cbor::key("added_at"),
                value: cbor::uint(rec.added_at),
            },
            MapEntry {
                key: cbor::key("nickname"),
                value: match &rec.nickname {
                    Some(s) => cbor::text(s),
                    None => cbor::null(),
                },
            },
            MapEntry {
                key: cbor::key("capabilities"),
                value: encode_text_array(&rec.capabilities),
            },
            MapEntry {
                key: cbor::key("introduced_by"),
                value: match rec.introduced_by {
                    Some(b) => cbor::bytes(&b),
                    None => cbor::null(),
                },
            },
        ];
        let map = cbor::encode_map(&entries);
        w.buf.extend_from_slice(&map);
    }
    w.into_bytes()
}

fn decode_relationship_array(
    r: &mut CborReader<'_>,
    _outer: &[u8],
) -> Result<Vec<RelationshipRecord>> {
    let n = r.read_array_header()?;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let m = r.read_map_header()?;
        if m != 7 {
            return Err(Error::CborDecode(format!(
                "Relationship record expected 7 keys, got {m}"
            )));
        }
        let expected = [
            "notes",
            "pinned",
            "address",
            "added_at",
            "nickname",
            "capabilities",
            "introduced_by",
        ];
        let mut rec = RelationshipRecord {
            address: [0; 32],
            nickname: None,
            introduced_by: None,
            capabilities: Vec::new(),
            notes: None,
            pinned: false,
            added_at: 0,
        };
        for k in expected {
            let got = r.read_text()?;
            if got != k {
                return Err(Error::CborNotCanonical(
                    "Relationship record keys not in canonical order",
                ));
            }
            match k {
                "notes" => {
                    let peek = *r
                        .remaining()
                        .first()
                        .ok_or_else(|| Error::CborDecode("missing notes".into()))?;
                    if peek == 0xF6 {
                        let _ = r.read_bytes_or_null()?;
                    } else {
                        rec.notes = Some(r.read_text()?.to_owned());
                    }
                }
                "pinned" => rec.pinned = r.read_bool()?,
                "address" => rec.address = read_32(r, "address")?,
                "added_at" => rec.added_at = r.read_u64()?,
                "nickname" => {
                    let peek = *r
                        .remaining()
                        .first()
                        .ok_or_else(|| Error::CborDecode("missing nickname".into()))?;
                    if peek == 0xF6 {
                        let _ = r.read_bytes_or_null()?;
                    } else {
                        rec.nickname = Some(r.read_text()?.to_owned());
                    }
                }
                "capabilities" => {
                    let count = r.read_array_header()?;
                    let mut caps = Vec::with_capacity(count);
                    for _ in 0..count {
                        caps.push(r.read_text()?.to_owned());
                    }
                    rec.capabilities = caps;
                }
                "introduced_by" => {
                    let peek = *r
                        .remaining()
                        .first()
                        .ok_or_else(|| Error::CborDecode("missing introduced_by".into()))?;
                    if peek == 0xF6 {
                        let _ = r.read_bytes_or_null()?;
                    } else {
                        rec.introduced_by = Some(read_32(r, "introduced_by")?);
                    }
                }
                _ => unreachable!(),
            }
        }
        out.push(rec);
    }
    Ok(out)
}

fn encode_text_array(items: &[String]) -> Vec<u8> {
    let mut w = CborWriter::new();
    w.write_array_header(items.len());
    for s in items {
        w.write_text(s);
    }
    w.into_bytes()
}

// =========================================================================
// StateDeltaPayload (0x29: co-holder → co-holder, live state sync)
// =========================================================================

/// One state operation in a `StateDeltaPayload`. Each variant is encoded
/// as a CBOR map with a `kind` discriminator and variant-specific fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeltaOp {
    ProfileUpdated {
        profile_wire: Vec<u8>,
    },
    ProfileCleared,
    RelationshipUpserted {
        record: RelationshipRecord,
    },
    RelationshipRemoved {
        address: [u8; 32],
    },
    RetiredObserved {
        address: [u8; 32],
    },
    LifecycleChanged {
        state: String,
    },
    CoHolderAdded {
        device_pubkey: [u8; 32],
        dial_addr: String,
    },
    CoHolderRemoved {
        device_pubkey: [u8; 32],
    },
}

const DELTA_KIND_PROFILE_UPDATED: &str = "profile_updated";
const DELTA_KIND_PROFILE_CLEARED: &str = "profile_cleared";
const DELTA_KIND_RELATIONSHIP_UPSERTED: &str = "relationship_upserted";
const DELTA_KIND_RELATIONSHIP_REMOVED: &str = "relationship_removed";
const DELTA_KIND_RETIRED_OBSERVED: &str = "retired_observed";
const DELTA_KIND_LIFECYCLE_CHANGED: &str = "lifecycle_changed";
const DELTA_KIND_COHOLDER_ADDED: &str = "cohol_added";
const DELTA_KIND_COHOLDER_REMOVED: &str = "cohol_removed";

impl DeltaOp {
    fn encode(&self) -> Vec<u8> {
        match self {
            DeltaOp::ProfileUpdated { profile_wire } => {
                // kind (5b) < profile_wire (13b)
                let entries = [
                    MapEntry {
                        key: cbor::key("kind"),
                        value: cbor::text(DELTA_KIND_PROFILE_UPDATED),
                    },
                    MapEntry {
                        key: cbor::key("profile_wire"),
                        value: cbor::bytes(profile_wire),
                    },
                ];
                cbor::encode_map(&entries)
            }
            DeltaOp::ProfileCleared => {
                let entries = [MapEntry {
                    key: cbor::key("kind"),
                    value: cbor::text(DELTA_KIND_PROFILE_CLEARED),
                }];
                cbor::encode_map(&entries)
            }
            DeltaOp::RelationshipUpserted { record } => {
                let inner = encode_single_relationship(record);
                let entries = [
                    MapEntry {
                        key: cbor::key("kind"),
                        value: cbor::text(DELTA_KIND_RELATIONSHIP_UPSERTED),
                    },
                    MapEntry {
                        key: cbor::key("record"),
                        value: inner,
                    },
                ];
                cbor::encode_map(&entries)
            }
            DeltaOp::RelationshipRemoved { address } => {
                let entries = [
                    MapEntry {
                        key: cbor::key("kind"),
                        value: cbor::text(DELTA_KIND_RELATIONSHIP_REMOVED),
                    },
                    MapEntry {
                        key: cbor::key("address"),
                        value: cbor::bytes(address),
                    },
                ];
                cbor::encode_map(&entries)
            }
            DeltaOp::RetiredObserved { address } => {
                let entries = [
                    MapEntry {
                        key: cbor::key("kind"),
                        value: cbor::text(DELTA_KIND_RETIRED_OBSERVED),
                    },
                    MapEntry {
                        key: cbor::key("address"),
                        value: cbor::bytes(address),
                    },
                ];
                cbor::encode_map(&entries)
            }
            DeltaOp::LifecycleChanged { state } => {
                let entries = [
                    MapEntry {
                        key: cbor::key("kind"),
                        value: cbor::text(DELTA_KIND_LIFECYCLE_CHANGED),
                    },
                    MapEntry {
                        key: cbor::key("state"),
                        value: cbor::text(state),
                    },
                ];
                cbor::encode_map(&entries)
            }
            DeltaOp::CoHolderAdded {
                device_pubkey,
                dial_addr,
            } => {
                // kind (5b) < dial_addr (10b) < device_pubkey (14b)
                let entries = [
                    MapEntry {
                        key: cbor::key("kind"),
                        value: cbor::text(DELTA_KIND_COHOLDER_ADDED),
                    },
                    MapEntry {
                        key: cbor::key("dial_addr"),
                        value: cbor::text(dial_addr),
                    },
                    MapEntry {
                        key: cbor::key("device_pubkey"),
                        value: cbor::bytes(device_pubkey),
                    },
                ];
                cbor::encode_map(&entries)
            }
            DeltaOp::CoHolderRemoved { device_pubkey } => {
                let entries = [
                    MapEntry {
                        key: cbor::key("kind"),
                        value: cbor::text(DELTA_KIND_COHOLDER_REMOVED),
                    },
                    MapEntry {
                        key: cbor::key("device_pubkey"),
                        value: cbor::bytes(device_pubkey),
                    },
                ];
                cbor::encode_map(&entries)
            }
        }
    }

    fn decode(r: &mut CborReader<'_>) -> Result<Self> {
        let n = r.read_map_header()?;
        if n == 0 {
            return Err(Error::CborDecode("empty DeltaOp map".into()));
        }
        // First key is always "kind".
        let k = r.read_text()?;
        if k != "kind" {
            return Err(Error::CborNotCanonical("DeltaOp: first key must be 'kind'"));
        }
        let kind = r.read_text()?.to_owned();
        match kind.as_str() {
            "profile_updated" => {
                if n != 2 {
                    return Err(Error::CborDecode("profile_updated expects 2 keys".into()));
                }
                expect_key(r, "profile_wire")?;
                let bytes = r.read_bytes()?.to_vec();
                Ok(DeltaOp::ProfileUpdated {
                    profile_wire: bytes,
                })
            }
            "profile_cleared" => {
                if n != 1 {
                    return Err(Error::CborDecode("profile_cleared expects 1 key".into()));
                }
                Ok(DeltaOp::ProfileCleared)
            }
            "relationship_upserted" => {
                if n != 2 {
                    return Err(Error::CborDecode(
                        "relationship_upserted expects 2 keys".into(),
                    ));
                }
                expect_key(r, "record")?;
                let record = decode_single_relationship(r)?;
                Ok(DeltaOp::RelationshipUpserted { record })
            }
            "relationship_removed" => {
                if n != 2 {
                    return Err(Error::CborDecode(
                        "relationship_removed expects 2 keys".into(),
                    ));
                }
                expect_key(r, "address")?;
                let address = read_32(r, "address")?;
                Ok(DeltaOp::RelationshipRemoved { address })
            }
            "retired_observed" => {
                if n != 2 {
                    return Err(Error::CborDecode("retired_observed expects 2 keys".into()));
                }
                expect_key(r, "address")?;
                let address = read_32(r, "address")?;
                Ok(DeltaOp::RetiredObserved { address })
            }
            "lifecycle_changed" => {
                if n != 2 {
                    return Err(Error::CborDecode("lifecycle_changed expects 2 keys".into()));
                }
                expect_key(r, "state")?;
                let state = r.read_text()?.to_owned();
                Ok(DeltaOp::LifecycleChanged { state })
            }
            "cohol_added" => {
                if n != 3 {
                    return Err(Error::CborDecode("cohol_added expects 3 keys".into()));
                }
                expect_key(r, "dial_addr")?;
                let dial_addr = r.read_text()?.to_owned();
                expect_key(r, "device_pubkey")?;
                let device_pubkey = read_32(r, "device_pubkey")?;
                Ok(DeltaOp::CoHolderAdded {
                    device_pubkey,
                    dial_addr,
                })
            }
            "cohol_removed" => {
                if n != 2 {
                    return Err(Error::CborDecode("cohol_removed expects 2 keys".into()));
                }
                expect_key(r, "device_pubkey")?;
                let device_pubkey = read_32(r, "device_pubkey")?;
                Ok(DeltaOp::CoHolderRemoved { device_pubkey })
            }
            other => Err(Error::CborDecode(format!(
                "DeltaOp: unknown kind '{other}'"
            ))),
        }
    }
}

fn expect_key(r: &mut CborReader<'_>, want: &str) -> Result<()> {
    let got = r.read_text()?;
    if got != want {
        return Err(Error::CborNotCanonical(
            "DeltaOp: keys not in canonical order",
        ));
    }
    Ok(())
}

fn encode_single_relationship(rec: &RelationshipRecord) -> Vec<u8> {
    // Same canonical order as encode_relationship_array's inner map.
    let entries = [
        MapEntry {
            key: cbor::key("notes"),
            value: match &rec.notes {
                Some(s) => cbor::text(s),
                None => cbor::null(),
            },
        },
        MapEntry {
            key: cbor::key("pinned"),
            value: cbor::boolean(rec.pinned),
        },
        MapEntry {
            key: cbor::key("address"),
            value: cbor::bytes(&rec.address),
        },
        MapEntry {
            key: cbor::key("added_at"),
            value: cbor::uint(rec.added_at),
        },
        MapEntry {
            key: cbor::key("nickname"),
            value: match &rec.nickname {
                Some(s) => cbor::text(s),
                None => cbor::null(),
            },
        },
        MapEntry {
            key: cbor::key("capabilities"),
            value: encode_text_array(&rec.capabilities),
        },
        MapEntry {
            key: cbor::key("introduced_by"),
            value: match rec.introduced_by {
                Some(b) => cbor::bytes(&b),
                None => cbor::null(),
            },
        },
    ];
    cbor::encode_map(&entries)
}

fn decode_single_relationship(r: &mut CborReader<'_>) -> Result<RelationshipRecord> {
    let m = r.read_map_header()?;
    if m != 7 {
        return Err(Error::CborDecode(format!(
            "Relationship record expected 7 keys, got {m}"
        )));
    }
    let expected = [
        "notes",
        "pinned",
        "address",
        "added_at",
        "nickname",
        "capabilities",
        "introduced_by",
    ];
    let mut rec = RelationshipRecord {
        address: [0; 32],
        nickname: None,
        introduced_by: None,
        capabilities: Vec::new(),
        notes: None,
        pinned: false,
        added_at: 0,
    };
    for k in expected {
        let got = r.read_text()?;
        if got != k {
            return Err(Error::CborNotCanonical(
                "Relationship record keys not in canonical order",
            ));
        }
        match k {
            "notes" => {
                let peek = *r
                    .remaining()
                    .first()
                    .ok_or_else(|| Error::CborDecode("missing notes".into()))?;
                if peek == 0xF6 {
                    let _ = r.read_bytes_or_null()?;
                } else {
                    rec.notes = Some(r.read_text()?.to_owned());
                }
            }
            "pinned" => rec.pinned = r.read_bool()?,
            "address" => rec.address = read_32(r, "address")?,
            "added_at" => rec.added_at = r.read_u64()?,
            "nickname" => {
                let peek = *r
                    .remaining()
                    .first()
                    .ok_or_else(|| Error::CborDecode("missing nickname".into()))?;
                if peek == 0xF6 {
                    let _ = r.read_bytes_or_null()?;
                } else {
                    rec.nickname = Some(r.read_text()?.to_owned());
                }
            }
            "capabilities" => {
                let count = r.read_array_header()?;
                let mut caps = Vec::with_capacity(count);
                for _ in 0..count {
                    caps.push(r.read_text()?.to_owned());
                }
                rec.capabilities = caps;
            }
            "introduced_by" => {
                let peek = *r
                    .remaining()
                    .first()
                    .ok_or_else(|| Error::CborDecode("missing introduced_by".into()))?;
                if peek == 0xF6 {
                    let _ = r.read_bytes_or_null()?;
                } else {
                    rec.introduced_by = Some(read_32(r, "introduced_by")?);
                }
            }
            _ => unreachable!(),
        }
    }
    Ok(rec)
}

/// State-delta envelope (0x29). Signed by the side's keypair (any
/// co-holder can produce one). Carries one or more `DeltaOp`s with a
/// single `applied_at` timestamp used by receivers for last-write-wins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateDeltaPayload {
    pub side: [u8; 32],
    pub ops: Vec<DeltaOp>,
    pub applied_at: u64,
    pub signature: [u8; SIGNATURE_LEN],
}

impl StateDeltaPayload {
    fn encode_unsigned(side: &[u8; 32], ops: &[DeltaOp], applied_at: u64) -> Vec<u8> {
        // "ops" (4b) < "side" (5b) < "applied_at" (11b)
        let entries = [
            MapEntry {
                key: cbor::key("ops"),
                value: encode_op_array(ops),
            },
            MapEntry {
                key: cbor::key("side"),
                value: cbor::bytes(side),
            },
            MapEntry {
                key: cbor::key("applied_at"),
                value: cbor::uint(applied_at),
            },
        ];
        cbor::encode_map(&entries)
    }

    pub fn sign(side_key: &SideKey, ops: Vec<DeltaOp>, applied_at: u64) -> Result<Self> {
        let side = side_key.public_bytes();
        let unsigned = Self::encode_unsigned(&side, &ops, applied_at);
        let digest = blake3::hash(&unsigned);
        let signature = side_key.sign(digest.as_bytes());
        Ok(Self {
            side,
            ops,
            applied_at,
            signature,
        })
    }

    pub fn to_wire_bytes(&self) -> Vec<u8> {
        // wire order: ops, side, signature, applied_at
        let entries = [
            MapEntry {
                key: cbor::key("ops"),
                value: encode_op_array(&self.ops),
            },
            MapEntry {
                key: cbor::key("side"),
                value: cbor::bytes(&self.side),
            },
            MapEntry {
                key: cbor::key("signature"),
                value: cbor::bytes(&self.signature),
            },
            MapEntry {
                key: cbor::key("applied_at"),
                value: cbor::uint(self.applied_at),
            },
        ];
        cbor::encode_map(&entries)
    }

    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = CborReader::new(bytes);
        let n = r.read_map_header()?;
        if n != 4 {
            return Err(Error::CborDecode(format!(
                "StateDelta expected 4 keys, got {n}"
            )));
        }
        let expected = ["ops", "side", "signature", "applied_at"];
        let mut ops: Option<Vec<DeltaOp>> = None;
        let mut side: Option<[u8; 32]> = None;
        let mut signature: Option<[u8; SIGNATURE_LEN]> = None;
        let mut applied_at: Option<u64> = None;
        for k in expected {
            let got = r.read_text()?;
            if got != k {
                return Err(Error::CborNotCanonical(
                    "StateDelta keys not in canonical order",
                ));
            }
            match k {
                "ops" => {
                    let count = r.read_array_header()?;
                    let mut out = Vec::with_capacity(count);
                    for _ in 0..count {
                        out.push(DeltaOp::decode(&mut r)?);
                    }
                    ops = Some(out);
                }
                "side" => side = Some(read_32(&mut r, "side")?),
                "signature" => {
                    let b = r.read_bytes()?;
                    if b.len() != SIGNATURE_LEN {
                        return Err(Error::BadFieldLength {
                            field: "signature",
                            expected: SIGNATURE_LEN,
                            got: b.len(),
                        });
                    }
                    let mut a = [0u8; SIGNATURE_LEN];
                    a.copy_from_slice(b);
                    signature = Some(a);
                }
                "applied_at" => applied_at = Some(r.read_u64()?),
                _ => unreachable!(),
            }
        }
        if !r.at_end() {
            return Err(Error::CborDecode("trailing bytes after StateDelta".into()));
        }
        let ops = ops.ok_or(Error::Invariant("missing ops"))?;
        let side = side.ok_or(Error::Invariant("missing side"))?;
        let signature = signature.ok_or(Error::Invariant("missing signature"))?;
        let applied_at = applied_at.ok_or(Error::Invariant("missing applied_at"))?;

        let unsigned = Self::encode_unsigned(&side, &ops, applied_at);
        let digest = blake3::hash(&unsigned);
        PublicKey::from_bytes(&side)?.verify(digest.as_bytes(), &signature)?;

        let p = Self {
            side,
            ops,
            applied_at,
            signature,
        };
        if p.to_wire_bytes() != bytes {
            return Err(Error::CborNotCanonical(
                "StateDelta bytes are not canonical re-encode",
            ));
        }
        Ok(p)
    }
}

fn encode_op_array(ops: &[DeltaOp]) -> Vec<u8> {
    let mut w = CborWriter::new();
    w.write_array_header(ops.len());
    for op in ops {
        w.buf.extend_from_slice(&op.encode());
    }
    w.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::MasterKey;

    fn fixture_side(seed: u8) -> SideKey {
        MasterKey::from_seed(&[seed; 32])
            .derive_side(&"work".into())
            .unwrap()
    }

    #[test]
    fn pairing_request_round_trip() {
        let device = fixture_side(0xAA);
        let p =
            PairingRequestPayload::sign([0x11; 32], &device, [0x22; 32], [0x33; PAIRING_NONCE_LEN])
                .unwrap();
        let bytes = p.to_wire_bytes();
        let parsed = PairingRequestPayload::from_wire_bytes(&bytes).unwrap();
        assert_eq!(parsed, p);
    }

    #[test]
    fn pairing_request_tampered_fails_verification() {
        let device = fixture_side(0xBB);
        let mut p =
            PairingRequestPayload::sign([0x11; 32], &device, [0x22; 32], [0x33; PAIRING_NONCE_LEN])
                .unwrap();
        p.signature[0] ^= 0xFF;
        let bytes = p.to_wire_bytes();
        let err = PairingRequestPayload::from_wire_bytes(&bytes).unwrap_err();
        assert!(matches!(err, Error::SignatureInvalid));
    }

    #[test]
    fn state_bundle_round_trip() {
        let side = fixture_side(0xCC);
        let p = StateBundlePayload::sign(
            &side,
            [0x77; 32],
            [0x88; PAIRING_NONCE_LEN],
            [0x99; KEY_NONCE_LEN],
            vec![0xAA, 0xBB, 0xCC, 0xDD],
        )
        .unwrap();
        let bytes = p.to_wire_bytes();
        let parsed = StateBundlePayload::from_wire_bytes(&bytes).unwrap();
        assert_eq!(parsed, p);
    }

    #[test]
    fn device_revoke_round_trip() {
        let side = fixture_side(0xDD);
        let p = DeviceRevokePayload::sign(
            &side,
            [0x55; 32],
            1_700_000_000,
            Some("lost phone".to_owned()),
        )
        .unwrap();
        let bytes = p.to_wire_bytes();
        let parsed = DeviceRevokePayload::from_wire_bytes(&bytes).unwrap();
        assert_eq!(parsed, p);
    }

    #[test]
    fn device_revoke_with_no_reason_round_trips() {
        let side = fixture_side(0xEE);
        let p = DeviceRevokePayload::sign(&side, [0x66; 32], 100, None).unwrap();
        let bytes = p.to_wire_bytes();
        let parsed = DeviceRevokePayload::from_wire_bytes(&bytes).unwrap();
        assert_eq!(parsed, p);
    }

    #[test]
    fn pairing_qr_round_trip() {
        let qr = PairingQr {
            side: [0x11; 32],
            nonce: [0x22; PAIRING_NONCE_LEN],
            dial_addr: "127.0.0.1:50001".to_owned(),
        };
        let s = qr.encode();
        assert!(s.starts_with(QR_SCHEME_PREFIX));
        let parsed = PairingQr::parse(&s).unwrap();
        assert_eq!(parsed, qr);
    }

    #[test]
    fn pairing_qr_rejects_bad_prefix() {
        assert!(PairingQr::parse("https://example.com").is_err());
    }

    #[test]
    fn contact_card_round_trip_full() {
        let c = ContactCard {
            side: [0xAB; 32],
            dial_addr: "192.168.1.7:50101".to_owned(),
            display_name: Some("Omar @ Cyberagora".to_owned()),
            side_label: Some("work".to_owned()),
        };
        let s = c.encode();
        assert!(s.starts_with(CONTACT_QR_SCHEME_PREFIX));
        let parsed = ContactCard::parse(&s).unwrap();
        assert_eq!(parsed, c);
    }

    #[test]
    fn contact_card_round_trip_no_optional_fields() {
        let c = ContactCard {
            side: [0x01; 32],
            dial_addr: "127.0.0.1:50001".to_owned(),
            display_name: None,
            side_label: None,
        };
        let s = c.encode();
        let parsed = ContactCard::parse(&s).unwrap();
        assert_eq!(parsed, c);
        // Empty strings round-trip as None, not Some("").
        assert!(parsed.display_name.is_none());
        assert!(parsed.side_label.is_none());
    }

    #[test]
    fn contact_card_rejects_bad_prefix() {
        assert!(ContactCard::parse("sidevers-pair:1:abc").is_err());
        assert!(ContactCard::parse("https://example.com").is_err());
        assert!(ContactCard::parse("").is_err());
    }

    #[test]
    fn contact_card_rejects_empty_dial_addr() {
        let c = ContactCard {
            side: [0x01; 32],
            dial_addr: String::new(),
            display_name: None,
            side_label: None,
        };
        let s = c.encode();
        // Encoder happily produces it; decoder must refuse.
        assert!(ContactCard::parse(&s).is_err());
    }

    #[test]
    fn contact_card_rejects_truncated_payload() {
        let c = ContactCard {
            side: [0x01; 32],
            dial_addr: "127.0.0.1:50001".to_owned(),
            display_name: None,
            side_label: None,
        };
        let s = c.encode();
        // Drop the last few base32 chars — the decoded buffer will
        // be missing its trailing dial_addr bytes.
        let truncated = &s[..s.len() - 6];
        assert!(ContactCard::parse(truncated).is_err());
    }

    #[test]
    fn contact_card_rejects_oversized_display_name() {
        let mut buf = Vec::new();
        buf.push(CONTACT_QR_VERSION);
        buf.extend_from_slice(&[0; 32]);
        // Claim a display_name length > CONTACT_DISPLAY_NAME_MAX, even
        // though the actual body would be that long.
        buf.extend_from_slice(&((CONTACT_DISPLAY_NAME_MAX as u16 + 1).to_be_bytes()));
        buf.extend(std::iter::repeat_n(b'x', CONTACT_DISPLAY_NAME_MAX + 1));
        buf.extend_from_slice(&0u16.to_be_bytes()); // empty side_label
        buf.extend_from_slice(&5u16.to_be_bytes());
        buf.extend_from_slice(b"a:b:c");
        let s = format!("{}{}", CONTACT_QR_SCHEME_PREFIX, base32_encode(&buf));
        assert!(ContactCard::parse(&s).is_err());
    }

    #[test]
    fn contact_card_rejects_wrong_version_byte() {
        let mut buf = Vec::new();
        buf.push(0x02); // not 0x01
        buf.extend_from_slice(&[0; 32]);
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&5u16.to_be_bytes());
        buf.extend_from_slice(b"a:b:c");
        let s = format!("{}{}", CONTACT_QR_SCHEME_PREFIX, base32_encode(&buf));
        assert!(ContactCard::parse(&s).is_err());
    }

    #[test]
    fn state_bundle_inner_round_trip() {
        let inner = StateBundleInner {
            side_seed: [0x42; 32],
            profile_wire: Some(vec![0xFE, 0xED, 0xBE, 0xEF]),
            relationships: vec![RelationshipRecord {
                address: [0xAA; 32],
                nickname: Some("alice".to_owned()),
                introduced_by: None,
                capabilities: vec!["direct-message".to_owned()],
                notes: None,
                pinned: true,
                added_at: 1,
            }],
            retired_sides: vec![[0xBB; 32]],
            lifecycle: "Active".to_owned(),
            co_holders: vec![[0xCC; 32], [0xDD; 32]],
            bundled_at: 1_700_000_000,
        };
        let bytes = inner.encode();
        let parsed = StateBundleInner::decode(&bytes).unwrap();
        assert_eq!(parsed, inner);
    }

    #[test]
    fn state_bundle_inner_empty_collections_round_trip() {
        let inner = StateBundleInner {
            side_seed: [0; 32],
            profile_wire: None,
            relationships: vec![],
            retired_sides: vec![],
            lifecycle: "Created".to_owned(),
            co_holders: vec![],
            bundled_at: 0,
        };
        let bytes = inner.encode();
        let parsed = StateBundleInner::decode(&bytes).unwrap();
        assert_eq!(parsed, inner);
    }

    #[test]
    fn state_delta_round_trip_all_variants() {
        let side = fixture_side(0x77);
        let ops = vec![
            DeltaOp::ProfileUpdated {
                profile_wire: vec![0xDE, 0xAD, 0xBE, 0xEF],
            },
            DeltaOp::ProfileCleared,
            DeltaOp::RelationshipUpserted {
                record: RelationshipRecord {
                    address: [0x11; 32],
                    nickname: Some("alice".to_owned()),
                    introduced_by: None,
                    capabilities: vec!["direct-message".to_owned()],
                    notes: None,
                    pinned: true,
                    added_at: 1,
                },
            },
            DeltaOp::RelationshipRemoved {
                address: [0x22; 32],
            },
            DeltaOp::RetiredObserved {
                address: [0x33; 32],
            },
            DeltaOp::LifecycleChanged {
                state: "Dormant".to_owned(),
            },
            DeltaOp::CoHolderAdded {
                device_pubkey: [0x44; 32],
                dial_addr: "127.0.0.1:51000".to_owned(),
            },
            DeltaOp::CoHolderRemoved {
                device_pubkey: [0x55; 32],
            },
        ];
        let p = StateDeltaPayload::sign(&side, ops.clone(), 1_700_000_000).unwrap();
        let bytes = p.to_wire_bytes();
        let parsed = StateDeltaPayload::from_wire_bytes(&bytes).unwrap();
        assert_eq!(parsed.ops, ops);
        assert_eq!(parsed.applied_at, 1_700_000_000);
    }

    #[test]
    fn state_delta_tampered_signature_fails() {
        let side = fixture_side(0x88);
        let mut p = StateDeltaPayload::sign(&side, vec![DeltaOp::ProfileCleared], 1).unwrap();
        p.signature[0] ^= 0xFF;
        let bytes = p.to_wire_bytes();
        let err = StateDeltaPayload::from_wire_bytes(&bytes).unwrap_err();
        assert!(matches!(err, Error::SignatureInvalid));
    }

    #[test]
    fn state_delta_empty_ops_round_trip() {
        let side = fixture_side(0x99);
        let p = StateDeltaPayload::sign(&side, vec![], 42).unwrap();
        let bytes = p.to_wire_bytes();
        let parsed = StateDeltaPayload::from_wire_bytes(&bytes).unwrap();
        assert_eq!(parsed.ops.len(), 0);
        assert_eq!(parsed.applied_at, 42);
    }
}
