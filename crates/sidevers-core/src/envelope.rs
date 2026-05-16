//! The signed CBOR envelope (protocol spec §3).
//!
//! Every message on the wire is wrapped in an envelope of identical shape;
//! only the payload varies. The envelope is signed over a BLAKE3 digest of
//! its own deterministic-CBOR encoding (minus the `sig` field), per §3.3.
//!
//! Canonical CBOR key order for the envelope map, sorted by RFC 8949 §4.2.1
//! (bytewise on encoded key bytes):
//!
//!   1. "t"        (0x61 0x74)
//!   2. "v"        (0x61 0x76)
//!   3. "to"       (0x62 0x74 0x6f)
//!   4. "ts"       (0x62 0x74 0x73)
//!   5. "sig"      (0x63 0x73 0x69 0x67)
//!   6. "from"     (0x64 0x66 0x72 0x6f 0x6d)
//!   7. "nonce"    (0x65 0x6e 0x6f 0x6e 0x63 0x65)
//!   8. "payload"  (0x67 0x70 0x61 0x79 0x6c 0x6f 0x61 0x64)

use std::time::{SystemTime, UNIX_EPOCH};

use crate::cbor::{self, CborReader, MapEntry};
use crate::error::{Error, Result};
use crate::keys::{PUBLIC_KEY_LEN, PublicKey, SIGNATURE_LEN, SideKey};

/// Protocol version this implementation speaks (§1.5).
pub const PROTOCOL_VERSION: u64 = 1;

/// Length of the per-envelope nonce in bytes (§3.2).
pub const NONCE_LEN: usize = 16;

/// Default replay tolerance for receivers: reject envelopes more than this
/// many seconds away from local time (§3.2: "more than 300 seconds skewed").
pub const DEFAULT_MAX_SKEW_SECS: u64 = 300;

/// Soft tolerance: envelopes between `DEFAULT_MAX_SKEW_SECS` and
/// `SOFT_MAX_SKEW_SECS` are still accepted but raise a warning, so
/// operators see clock-skew problems instead of silently dropping all
/// traffic when one side's clock drifts. Phase 1.H1 graceful fallback.
/// Envelopes above this threshold are dropped as before.
pub const SOFT_MAX_SKEW_SECS: u64 = 900;

/// Message type tag (§3.5, Appendix A). Stored on the wire as a CBOR uint;
/// every type defined in protocol v1 fits in one byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MessageType(pub u8);

impl MessageType {
    // Handshake (§4)
    pub const HELLO: Self = Self(0x10);
    pub const HELLO_BACK: Self = Self(0x11);
    pub const CONFIRM: Self = Self(0x12);

    // Direct (§3.9)
    pub const DIRECT_MESSAGE: Self = Self(0x20);
    pub const DIRECT_RECEIPT: Self = Self(0x21);
    pub const DIRECT_TYPING: Self = Self(0x22);
    // Side-level (§7) — Phase 1.5d extends the Direct range to carry
    // profile fetch/deliver and side retirement records. These are
    // side-to-side metadata; they reuse Direct intent and replay/freshness.
    pub const PROFILE_FETCH: Self = Self(0x23);
    pub const PROFILE_DELIVER: Self = Self(0x24);
    pub const SIDE_RETIREMENT: Self = Self(0x25);
    // Multi-device co-holder pairing (§7.5) — Phase 1.5f Track C.
    pub const DEVICE_PAIRING_REQUEST: Self = Self(0x26);
    pub const DEVICE_STATE_BUNDLE: Self = Self(0x27);
    pub const DEVICE_REVOKE: Self = Self(0x28);
    /// Phase 1.5g: live state delta pushed between co-holders (§7.5).
    pub const STATE_DELTA: Self = Self(0x29);
    /// Phase 1.G: publish a `LinkageProof` (§2.7) on the wire so a peer can
    /// independently verify two sides agreed to be linked. The envelope
    /// payload is the LinkageProof's canonical CBOR (`LinkageProof::to_wire_bytes`).
    /// Sent on a Direct-intent session.
    pub const LINKAGE_PUBLISH: Self = Self(0x2A);

    // Storage (§5) — Month 3
    pub const STORAGE_GET: Self = Self(0x30);
    pub const STORAGE_HAVE: Self = Self(0x31);
    pub const STORAGE_MISS: Self = Self(0x32);
    pub const STORAGE_OFFER: Self = Self(0x33);
    pub const STORAGE_WANT: Self = Self(0x34);
    pub const STORAGE_RETRACT: Self = Self(0x35);

    // Discovery (§6) — Month 4
    pub const PEER_ASK: Self = Self(0x40);
    pub const PEER_TELL: Self = Self(0x41);
    pub const RENDEZVOUS: Self = Self(0x42);
    pub const RENDEZVOUS_ACK: Self = Self(0x43);
    pub const FORWARD_STORE: Self = Self(0x44);
    pub const FORWARD_DELIVER: Self = Self(0x45);

    // Verse (§8) — Phase 1.5.
    pub const CONTRACT_FETCH: Self = Self(0x50);
    pub const CONTRACT_DELIVER: Self = Self(0x51);
    pub const JOIN_REQUEST: Self = Self(0x52);
    pub const JOIN_ACCEPT: Self = Self(0x53);
    pub const JOIN_DECLINE: Self = Self(0x54);
    pub const VERSE_LEAVE: Self = Self(0x55);
    pub const VERSE_REMOVE: Self = Self(0x56);
    pub const VERSE_POST: Self = Self(0x57);
    pub const VERSE_AMEND: Self = Self(0x58);
    pub const VERSE_RECONSENT: Self = Self(0x59);

    // Public layer (§9) — Phase 2, but Announcement gossips in Month 4.
    pub const HANDLE_RESOLVE: Self = Self(0x60);
    pub const HANDLE_ATTEST: Self = Self(0x61);
    pub const PAGE_PUBLISH: Self = Self(0x62);
    pub const PAGE_FETCH: Self = Self(0x63);
    pub const PAGE_DELIVER: Self = Self(0x64);
    pub const ANNOUNCEMENT: Self = Self(0x65);
    pub const DIRECTORY_ENTRY: Self = Self(0x66);

    pub fn category(self) -> MessageCategory {
        match self.0 {
            0x00..=0x0F => MessageCategory::Reserved,
            0x10..=0x1F => MessageCategory::Handshake,
            0x20..=0x2F => MessageCategory::Direct,
            0x30..=0x3F => MessageCategory::Storage,
            0x40..=0x4F => MessageCategory::Discovery,
            0x50..=0x5F => MessageCategory::Verse,
            0x60..=0x6F => MessageCategory::Public,
            0x70..=0xEF => MessageCategory::Future,
            0xF0..=0xFF => MessageCategory::Extension,
        }
    }
}

/// Spec §3.5 ranges. Different categories have different unknown-type handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageCategory {
    /// 0x00–0x0F: undefined in v1; receivers MUST silently drop.
    Reserved,
    /// 0x10–0x1F: handshake (§4).
    Handshake,
    /// 0x20–0x2F: direct unicast (§3.9).
    Direct,
    /// 0x30–0x3F: storage (§5).
    Storage,
    /// 0x40–0x4F: discovery (§6).
    Discovery,
    /// 0x50–0x5F: verse (§8) — Phase 1.5.
    Verse,
    /// 0x60–0x6F: public layer (§9) — Phase 2.
    Public,
    /// 0x70–0xEF: reserved for future minor versions; receivers MUST trigger
    /// a type-unknown error rather than silently dropping.
    Future,
    /// 0xF0–0xFF: vendor extensions; silently drop if unknown.
    Extension,
}

/// A fully-signed envelope ready for the wire (or just parsed from it).
#[derive(Clone, PartialEq, Eq)]
pub struct Envelope {
    pub version: u64,
    pub message_type: MessageType,
    pub from: [u8; PUBLIC_KEY_LEN],
    pub to: Option<[u8; PUBLIC_KEY_LEN]>,
    pub timestamp: u64,
    pub nonce: [u8; NONCE_LEN],
    pub payload: Vec<u8>,
    pub sig: [u8; SIGNATURE_LEN],
}

impl core::fmt::Debug for Envelope {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Identifier fields are truncated to a `LogId` prefix so that
        // `tracing::debug!(envelope = ?env, ...)` cannot leak full peer
        // pubkeys or replay-cache keys into log output.
        f.debug_struct("Envelope")
            .field("v", &self.version)
            .field("t", &format_args!("0x{:02X}", self.message_type.0))
            .field("from", &crate::LogId::new(&self.from))
            .field("to", &self.to.as_ref().map(|b| crate::LogId::new(b)))
            .field("ts", &self.timestamp)
            .field("nonce", &crate::LogId::new(&self.nonce))
            .field("payload_len", &self.payload.len())
            .field("sig", &crate::LogId::new(&self.sig[..]))
            .finish()
    }
}

impl Envelope {
    /// Build the deterministic-CBOR encoding of the "to-be-signed" portion
    /// of the envelope: the 7 non-sig fields in canonical key order.
    fn encode_unsigned(
        version: u64,
        message_type: MessageType,
        from: &[u8; PUBLIC_KEY_LEN],
        to: Option<&[u8; PUBLIC_KEY_LEN]>,
        timestamp: u64,
        nonce: &[u8; NONCE_LEN],
        payload: &[u8],
    ) -> Vec<u8> {
        let entries = [
            MapEntry {
                key: cbor::key("t"),
                value: cbor::uint(message_type.0 as u64),
            },
            MapEntry {
                key: cbor::key("v"),
                value: cbor::uint(version),
            },
            MapEntry {
                key: cbor::key("to"),
                value: match to {
                    Some(addr) => cbor::bytes(addr),
                    None => cbor::null(),
                },
            },
            MapEntry {
                key: cbor::key("ts"),
                value: cbor::uint(timestamp),
            },
            MapEntry {
                key: cbor::key("from"),
                value: cbor::bytes(from),
            },
            MapEntry {
                key: cbor::key("nonce"),
                value: cbor::bytes(nonce),
            },
            MapEntry {
                key: cbor::key("payload"),
                value: cbor::bytes(payload),
            },
        ];
        cbor::encode_map(&entries)
    }

    /// Encode the full signed envelope for the wire (8 fields, canonical order).
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let entries = [
            MapEntry {
                key: cbor::key("t"),
                value: cbor::uint(self.message_type.0 as u64),
            },
            MapEntry {
                key: cbor::key("v"),
                value: cbor::uint(self.version),
            },
            MapEntry {
                key: cbor::key("to"),
                value: match self.to {
                    Some(addr) => cbor::bytes(&addr),
                    None => cbor::null(),
                },
            },
            MapEntry {
                key: cbor::key("ts"),
                value: cbor::uint(self.timestamp),
            },
            MapEntry {
                key: cbor::key("sig"),
                value: cbor::bytes(&self.sig),
            },
            MapEntry {
                key: cbor::key("from"),
                value: cbor::bytes(&self.from),
            },
            MapEntry {
                key: cbor::key("nonce"),
                value: cbor::bytes(&self.nonce),
            },
            MapEntry {
                key: cbor::key("payload"),
                value: cbor::bytes(&self.payload),
            },
        ];
        cbor::encode_map(&entries)
    }

    /// Construct, sign, and return an envelope from raw fields. Spec §3.3:
    /// the signature is over `BLAKE3(deterministic-CBOR of envelope-minus-sig)`.
    ///
    /// The signing side's public key MUST match `from`; this is enforced by
    /// taking the side as a parameter and copying its pubkey into `from`.
    pub fn sign(
        message_type: MessageType,
        side: &SideKey,
        to: Option<[u8; PUBLIC_KEY_LEN]>,
        payload: Vec<u8>,
    ) -> Result<Self> {
        let nonce = random_nonce()?;
        let timestamp = now_unix_seconds()?;
        Self::sign_with(message_type, side, to, payload, timestamp, nonce)
    }

    /// Like `sign`, but with caller-supplied timestamp and nonce. Useful for
    /// deterministic tests and for replaying signed envelopes off disk.
    pub fn sign_with(
        message_type: MessageType,
        side: &SideKey,
        to: Option<[u8; PUBLIC_KEY_LEN]>,
        payload: Vec<u8>,
        timestamp: u64,
        nonce: [u8; NONCE_LEN],
    ) -> Result<Self> {
        let from = side.public_bytes();
        let unsigned = Self::encode_unsigned(
            PROTOCOL_VERSION,
            message_type,
            &from,
            to.as_ref(),
            timestamp,
            &nonce,
            &payload,
        );
        let digest = blake3::hash(&unsigned);
        let sig = side.sign(digest.as_bytes());

        Ok(Self {
            version: PROTOCOL_VERSION,
            message_type,
            from,
            to,
            timestamp,
            nonce,
            payload,
            sig,
        })
    }

    /// Parse + verify an envelope from wire bytes (§3.3).
    ///
    /// Verification reconstructs the "to-be-signed" encoding from the parsed
    /// fields rather than locating the original bytes within the input.
    /// This is sound because the canonical encoding is deterministic: any
    /// non-canonical input is rejected by the CBOR reader (which enforces
    /// shortest-form length encoding) or by the post-parse re-encode check
    /// (which fails if the input map keys were in a different order).
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self> {
        let mut reader = CborReader::new(bytes);
        let map_len = reader.read_map_header()?;
        if map_len != 8 {
            return Err(Error::CborDecode(format!(
                "envelope expected 8-key map, got {map_len}"
            )));
        }

        // Track which fields we've seen, and enforce canonical key order.
        let expected_keys = ["t", "v", "to", "ts", "sig", "from", "nonce", "payload"];
        let mut version: Option<u64> = None;
        let mut t_byte: Option<u8> = None;
        let mut to: Option<Option<[u8; PUBLIC_KEY_LEN]>> = None;
        let mut ts: Option<u64> = None;
        let mut sig: Option<[u8; SIGNATURE_LEN]> = None;
        let mut from: Option<[u8; PUBLIC_KEY_LEN]> = None;
        let mut nonce: Option<[u8; NONCE_LEN]> = None;
        let mut payload: Option<Vec<u8>> = None;

        for expected in expected_keys {
            let k = reader.read_text()?;
            if k != expected {
                return Err(Error::CborNotCanonical(
                    "envelope map keys not in canonical order",
                ));
            }
            match expected {
                "t" => {
                    let v = reader.read_u64()?;
                    if v > 0xFF {
                        return Err(Error::CborDecode(format!(
                            "message type out of u8 range: {v}"
                        )));
                    }
                    t_byte = Some(v as u8);
                }
                "v" => version = Some(reader.read_u64()?),
                "to" => {
                    to = Some(match reader.read_bytes_or_null()? {
                        None => None,
                        Some(b) => {
                            if b.len() != PUBLIC_KEY_LEN {
                                return Err(Error::BadFieldLength {
                                    field: "to",
                                    expected: PUBLIC_KEY_LEN,
                                    got: b.len(),
                                });
                            }
                            let mut arr = [0u8; PUBLIC_KEY_LEN];
                            arr.copy_from_slice(b);
                            Some(arr)
                        }
                    });
                }
                "ts" => ts = Some(reader.read_u64()?),
                "sig" => {
                    let b = reader.read_bytes()?;
                    if b.len() != SIGNATURE_LEN {
                        return Err(Error::BadFieldLength {
                            field: "sig",
                            expected: SIGNATURE_LEN,
                            got: b.len(),
                        });
                    }
                    let mut arr = [0u8; SIGNATURE_LEN];
                    arr.copy_from_slice(b);
                    sig = Some(arr);
                }
                "from" => {
                    let b = reader.read_bytes()?;
                    if b.len() != PUBLIC_KEY_LEN {
                        return Err(Error::BadFieldLength {
                            field: "from",
                            expected: PUBLIC_KEY_LEN,
                            got: b.len(),
                        });
                    }
                    let mut arr = [0u8; PUBLIC_KEY_LEN];
                    arr.copy_from_slice(b);
                    from = Some(arr);
                }
                "nonce" => {
                    let b = reader.read_bytes()?;
                    if b.len() != NONCE_LEN {
                        return Err(Error::BadFieldLength {
                            field: "nonce",
                            expected: NONCE_LEN,
                            got: b.len(),
                        });
                    }
                    let mut arr = [0u8; NONCE_LEN];
                    arr.copy_from_slice(b);
                    nonce = Some(arr);
                }
                "payload" => payload = Some(reader.read_bytes()?.to_vec()),
                _ => unreachable!(),
            }
        }

        if !reader.at_end() {
            return Err(Error::CborDecode("trailing bytes after envelope".into()));
        }

        let version = version.ok_or(Error::Invariant("missing version"))?;
        let message_type = MessageType(t_byte.ok_or(Error::Invariant("missing message type"))?);
        let from = from.ok_or(Error::Invariant("missing from"))?;
        let to = to.ok_or(Error::Invariant("missing to"))?;
        let timestamp = ts.ok_or(Error::Invariant("missing timestamp"))?;
        let nonce = nonce.ok_or(Error::Invariant("missing nonce"))?;
        let payload = payload.ok_or(Error::Invariant("missing payload"))?;
        let sig = sig.ok_or(Error::Invariant("missing sig"))?;

        if version != PROTOCOL_VERSION {
            return Err(Error::UnsupportedVersion { got: version });
        }

        // Verify signature.
        let unsigned = Self::encode_unsigned(
            version,
            message_type,
            &from,
            to.as_ref(),
            timestamp,
            &nonce,
            &payload,
        );
        let digest = blake3::hash(&unsigned);
        let pk = PublicKey::from_bytes(&from)?;
        pk.verify(digest.as_bytes(), &sig)?;

        let envelope = Self {
            version,
            message_type,
            from,
            to,
            timestamp,
            nonce,
            payload,
            sig,
        };

        // Belt-and-braces: re-encode the canonical wire bytes and assert the
        // input matched. If a caller hand-crafted an envelope with a
        // non-canonical encoding that nevertheless decoded, this catches it.
        if envelope.to_wire_bytes() != bytes {
            return Err(Error::CborNotCanonical(
                "envelope bytes are not canonical re-encode",
            ));
        }

        Ok(envelope)
    }

    /// Reject envelopes whose timestamp is more than `max_skew_secs` away
    /// from `now_unix_seconds`. Per §3.2 the SHOULD-recommended bound is 300 s.
    pub fn check_freshness(&self, now: u64, max_skew_secs: u64) -> Result<()> {
        if now.abs_diff(self.timestamp) > max_skew_secs {
            Err(Error::TimestampSkewed { max_skew_secs })
        } else {
            Ok(())
        }
    }
}

/// Read 16 fresh bytes from the OS CSPRNG for use as a per-envelope nonce.
pub fn random_nonce() -> Result<[u8; NONCE_LEN]> {
    let mut n = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut n).map_err(|e| Error::CsprngUnavailable(e.to_string()))?;
    Ok(n)
}

/// Wall-clock unix seconds. Returns an error if the system clock is set
/// before the epoch (which would be a misconfiguration).
pub fn now_unix_seconds() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| Error::Invariant("system clock before unix epoch"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::MasterKey;

    fn fixture_side() -> SideKey {
        // Deterministic master + side for repeatable byte-level tests.
        let master = MasterKey::from_seed(&[0x42u8; 32]);
        master.derive_side(&"work".into()).unwrap()
    }

    #[test]
    fn sign_and_verify_roundtrip_unicast() {
        let alice = fixture_side();
        let bob_pk = MasterKey::from_seed(&[0xAAu8; 32])
            .derive_side(&"close".into())
            .unwrap()
            .public_bytes();

        let env = Envelope::sign(
            MessageType::DIRECT_MESSAGE,
            &alice,
            Some(bob_pk),
            b"hello".to_vec(),
        )
        .unwrap();

        let bytes = env.to_wire_bytes();
        let parsed = Envelope::from_wire_bytes(&bytes).unwrap();
        assert_eq!(parsed, env);
        assert_eq!(parsed.message_type, MessageType::DIRECT_MESSAGE);
        assert_eq!(parsed.to.unwrap(), bob_pk);
    }

    #[test]
    fn sign_and_verify_roundtrip_broadcast() {
        let alice = fixture_side();
        let env = Envelope::sign(
            MessageType(0x65), // hypothetical announcement; just exercises broadcast
            &alice,
            None,
            b"public news".to_vec(),
        )
        .unwrap();
        let bytes = env.to_wire_bytes();
        let parsed = Envelope::from_wire_bytes(&bytes).unwrap();
        assert!(parsed.to.is_none());
        assert_eq!(parsed.payload, b"public news");
    }

    #[test]
    fn tampered_payload_fails_verification() {
        let alice = fixture_side();
        let env =
            Envelope::sign(MessageType::DIRECT_MESSAGE, &alice, None, b"hello".to_vec()).unwrap();
        let mut bytes = env.to_wire_bytes();
        // Find the payload byte 'h' and flip it.
        let i = bytes.iter().position(|&b| b == b'h').unwrap();
        bytes[i] ^= 0x01;
        let err = Envelope::from_wire_bytes(&bytes).unwrap_err();
        assert!(matches!(err, Error::SignatureInvalid));
    }

    #[test]
    fn tampered_signature_fails_verification() {
        let alice = fixture_side();
        let mut env =
            Envelope::sign(MessageType::DIRECT_MESSAGE, &alice, None, b"hi".to_vec()).unwrap();
        env.sig[0] ^= 0xFF;
        let bytes = env.to_wire_bytes();
        let err = Envelope::from_wire_bytes(&bytes).unwrap_err();
        assert!(matches!(err, Error::SignatureInvalid));
    }

    // Phase 1.H1 wiring depends on SOFT > DEFAULT so the soft band is
    // non-empty. If someone shrinks SOFT below DEFAULT the graceful-
    // fallback band collapses and we silently regress to the old
    // hard-cutoff behavior. A const-time check trips compilation.
    const _: () = assert!(SOFT_MAX_SKEW_SECS > DEFAULT_MAX_SKEW_SECS);

    #[test]
    fn freshness_window_enforced() {
        let alice = fixture_side();
        let env = Envelope::sign_with(
            MessageType::DIRECT_MESSAGE,
            &alice,
            None,
            b"hi".to_vec(),
            1_000_000,
            [9u8; NONCE_LEN],
        )
        .unwrap();
        assert!(
            env.check_freshness(1_000_000, DEFAULT_MAX_SKEW_SECS)
                .is_ok()
        );
        assert!(
            env.check_freshness(1_000_200, DEFAULT_MAX_SKEW_SECS)
                .is_ok()
        );
        assert!(
            env.check_freshness(1_000_400, DEFAULT_MAX_SKEW_SECS)
                .is_err()
        );
    }

    #[test]
    fn deterministic_signing_is_deterministic() {
        let alice = fixture_side();
        let nonce = [3u8; NONCE_LEN];
        let env1 = Envelope::sign_with(
            MessageType::DIRECT_MESSAGE,
            &alice,
            None,
            b"hi".to_vec(),
            42,
            nonce,
        )
        .unwrap();
        let env2 = Envelope::sign_with(
            MessageType::DIRECT_MESSAGE,
            &alice,
            None,
            b"hi".to_vec(),
            42,
            nonce,
        )
        .unwrap();
        // Ed25519 is deterministic — same key + same message = same signature.
        assert_eq!(env1.sig, env2.sig);
        assert_eq!(env1.to_wire_bytes(), env2.to_wire_bytes());
    }

    #[test]
    fn rejects_envelope_with_wrong_version() {
        let alice = fixture_side();
        let env = Envelope::sign_with(
            MessageType::DIRECT_MESSAGE,
            &alice,
            None,
            b"hi".to_vec(),
            42,
            [3u8; NONCE_LEN],
        )
        .unwrap();
        let mut bad = env.clone();
        bad.version = 99;
        // We can't sign with the wrong version using our normal path, so build
        // the bytes directly and try to parse them.
        let bytes = bad.to_wire_bytes();
        // Note: the signature was computed over v=1 so this also fails sig,
        // but UnsupportedVersion is checked first.
        let err = Envelope::from_wire_bytes(&bytes).unwrap_err();
        assert!(
            matches!(err, Error::UnsupportedVersion { got: 99 }),
            "got {err:?}"
        );
    }

    #[test]
    fn message_type_category_matches_spec() {
        assert_eq!(MessageType(0x00).category(), MessageCategory::Reserved);
        assert_eq!(MessageType::HELLO.category(), MessageCategory::Handshake);
        assert_eq!(
            MessageType::DIRECT_MESSAGE.category(),
            MessageCategory::Direct
        );
        assert_eq!(
            MessageType::STORAGE_GET.category(),
            MessageCategory::Storage
        );
        assert_eq!(MessageType::PEER_ASK.category(), MessageCategory::Discovery);
        assert_eq!(MessageType(0x50).category(), MessageCategory::Verse);
        assert_eq!(MessageType(0x60).category(), MessageCategory::Public);
        assert_eq!(MessageType(0x80).category(), MessageCategory::Future);
        assert_eq!(MessageType(0xF0).category(), MessageCategory::Extension);
    }
}
