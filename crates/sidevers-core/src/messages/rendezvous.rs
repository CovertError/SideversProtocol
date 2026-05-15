//! NAT-traversal rendezvous payloads — Appendix A range 0x42–0x43 (§6.6).
//!
//! Two payload types:
//!
//!   * 0x42 Rendezvous     — initiator → relay: "help me reach this peer"
//!   * 0x43 RendezvousAck  — relay → initiator: "here are candidate endpoints"
//!
//! For real NAT traversal the relay sends a RendezvousAck to *both* sides
//! simultaneously so each can attempt a coordinated hole-punching connect.
//! For Month-4 localhost integration we simulate the protocol-level
//! exchange; the actual UDP hole-punch is a refinement.
//!
//! Canonical CBOR key order (RFC 8949 §4.2.1, bytewise on encoded keys):
//!
//!   RendezvousPayload     : target
//!   RendezvousAckPayload  : target < endpoints  (shorter key first)

use crate::cbor::{self, CborReader, MapEntry};
use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RendezvousPayload {
    /// The peer (side public key) the initiator wants to reach.
    pub target: [u8; 32],
}

impl RendezvousPayload {
    pub fn encode(&self) -> Vec<u8> {
        let entries = [MapEntry {
            key: cbor::text("target"),
            value: cbor::bytes(&self.target),
        }];
        cbor::encode_map(&entries)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = CborReader::new(bytes);
        let n = r.read_map_header()?;
        if n != 1 {
            return Err(Error::CborDecode(format!(
                "Rendezvous expected 1 key, got {n}"
            )));
        }
        if r.read_text()? != "target" {
            return Err(Error::CborNotCanonical("expected 'target'"));
        }
        let b = r.read_bytes()?;
        if b.len() != 32 {
            return Err(Error::BadFieldLength {
                field: "target",
                expected: 32,
                got: b.len(),
            });
        }
        let mut target = [0u8; 32];
        target.copy_from_slice(b);
        Ok(Self { target })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RendezvousAckPayload {
    /// The peer this ack is informing about.
    pub target: [u8; 32],
    /// Candidate endpoints (host:port strings) for the target.
    pub endpoints: Vec<String>,
}

impl RendezvousAckPayload {
    pub fn encode(&self) -> Vec<u8> {
        let mut header = cbor::CborWriter::new();
        header.write_array_header(self.endpoints.len());
        let mut ep_bytes = header.into_bytes();
        for s in &self.endpoints {
            ep_bytes.extend_from_slice(&cbor::text(s));
        }
        let entries = [
            MapEntry {
                key: cbor::text("target"),
                value: cbor::bytes(&self.target),
            },
            MapEntry {
                key: cbor::text("endpoints"),
                value: ep_bytes,
            },
        ];
        cbor::encode_map(&entries)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = CborReader::new(bytes);
        let n = r.read_map_header()?;
        if n != 2 {
            return Err(Error::CborDecode(format!(
                "RendezvousAck expected 2 keys, got {n}"
            )));
        }
        if r.read_text()? != "target" {
            return Err(Error::CborNotCanonical("expected 'target' first"));
        }
        let b = r.read_bytes()?;
        if b.len() != 32 {
            return Err(Error::BadFieldLength {
                field: "target",
                expected: 32,
                got: b.len(),
            });
        }
        let mut target = [0u8; 32];
        target.copy_from_slice(b);
        if r.read_text()? != "endpoints" {
            return Err(Error::CborNotCanonical("expected 'endpoints' second"));
        }
        let cnt = r.read_array_header()?;
        let mut endpoints = Vec::with_capacity(cnt);
        for _ in 0..cnt {
            endpoints.push(r.read_text()?.to_owned());
        }
        Ok(Self { target, endpoints })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rendezvous_roundtrip() {
        let p = RendezvousPayload { target: [7u8; 32] };
        let bytes = p.encode();
        let decoded = RendezvousPayload::decode(&bytes).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn rendezvous_ack_roundtrip() {
        let p = RendezvousAckPayload {
            target: [0x33; 32],
            endpoints: vec!["1.2.3.4:4242".into(), "[::1]:4242".into()],
        };
        let bytes = p.encode();
        let decoded = RendezvousAckPayload::decode(&bytes).unwrap();
        assert_eq!(decoded, p);
    }
}
