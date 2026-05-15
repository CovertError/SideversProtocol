//! Store-and-forward payloads — Appendix A range 0x44–0x45 (§6.7).
//!
//! Two payload types:
//!
//!   * 0x44 ForwardStore    — sender → forwarder: "hold this for later"
//!   * 0x45 ForwardDeliver  — forwarder → recipient: "I held this for you"
//!
//! The forwarder sees only the outer envelope's `to` field — the inner
//! envelope is end-to-end encrypted to the recipient (§3.4), so the
//! forwarder cannot read its payload.
//!
//! Canonical CBOR key order:
//!
//!   ForwardStorePayload    : envelope < ttl_secs < recipient
//!   ForwardDeliverPayload  : envelope < stored_at

use crate::cbor::{self, CborReader, MapEntry};
use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardStorePayload {
    /// The inner envelope to deliver later. Already signed and (for unicast)
    /// payload-encrypted by the sender per spec §3.4.
    pub envelope: Vec<u8>,
    /// Recipient side address — used by the forwarder for routing only;
    /// duplicates the inner envelope's `to` field.
    pub recipient: [u8; 32],
    /// Time-to-hold, in seconds. Spec §6.7 default is 7 days.
    pub ttl_secs: u64,
}

impl ForwardStorePayload {
    pub fn encode(&self) -> Vec<u8> {
        let entries = [
            MapEntry {
                key: cbor::text("envelope"),
                value: cbor::bytes(&self.envelope),
            },
            MapEntry {
                key: cbor::text("ttl_secs"),
                value: cbor::uint(self.ttl_secs),
            },
            MapEntry {
                key: cbor::text("recipient"),
                value: cbor::bytes(&self.recipient),
            },
        ];
        cbor::encode_map(&entries)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = CborReader::new(bytes);
        let n = r.read_map_header()?;
        if n != 3 {
            return Err(Error::CborDecode(format!(
                "ForwardStore expected 3 keys, got {n}"
            )));
        }
        if r.read_text()? != "envelope" {
            return Err(Error::CborNotCanonical("expected 'envelope' first"));
        }
        let envelope = r.read_bytes()?.to_vec();
        if r.read_text()? != "ttl_secs" {
            return Err(Error::CborNotCanonical("expected 'ttl_secs' second"));
        }
        let ttl_secs = r.read_u64()?;
        if r.read_text()? != "recipient" {
            return Err(Error::CborNotCanonical("expected 'recipient' third"));
        }
        let b = r.read_bytes()?;
        if b.len() != 32 {
            return Err(Error::BadFieldLength {
                field: "recipient",
                expected: 32,
                got: b.len(),
            });
        }
        let mut recipient = [0u8; 32];
        recipient.copy_from_slice(b);
        Ok(Self {
            envelope,
            recipient,
            ttl_secs,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardDeliverPayload {
    /// The previously-stored inner envelope.
    pub envelope: Vec<u8>,
    /// Unix-seconds the forwarder first received it.
    pub stored_at: u64,
}

impl ForwardDeliverPayload {
    pub fn encode(&self) -> Vec<u8> {
        let entries = [
            MapEntry {
                key: cbor::text("envelope"),
                value: cbor::bytes(&self.envelope),
            },
            MapEntry {
                key: cbor::text("stored_at"),
                value: cbor::uint(self.stored_at),
            },
        ];
        cbor::encode_map(&entries)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = CborReader::new(bytes);
        let n = r.read_map_header()?;
        if n != 2 {
            return Err(Error::CborDecode(format!(
                "ForwardDeliver expected 2 keys, got {n}"
            )));
        }
        if r.read_text()? != "envelope" {
            return Err(Error::CborNotCanonical("expected 'envelope' first"));
        }
        let envelope = r.read_bytes()?.to_vec();
        if r.read_text()? != "stored_at" {
            return Err(Error::CborNotCanonical("expected 'stored_at' second"));
        }
        let stored_at = r.read_u64()?;
        Ok(Self {
            envelope,
            stored_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forward_store_roundtrip() {
        let p = ForwardStorePayload {
            envelope: vec![0x01, 0x02, 0x03],
            recipient: [9u8; 32],
            ttl_secs: 7 * 24 * 60 * 60,
        };
        let bytes = p.encode();
        let decoded = ForwardStorePayload::decode(&bytes).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn forward_deliver_roundtrip() {
        let p = ForwardDeliverPayload {
            envelope: vec![0xAA, 0xBB],
            stored_at: 1_700_000_000,
        };
        let bytes = p.encode();
        let decoded = ForwardDeliverPayload::decode(&bytes).unwrap();
        assert_eq!(decoded, p);
    }
}
