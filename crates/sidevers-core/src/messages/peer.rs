//! Peer-exchange payloads — Appendix A range 0x40–0x41 (§6.4).
//!
//! Two payload types:
//!
//!   * 0x40 PeerAsk   — "tell me about peers you know"
//!   * 0x41 PeerTell  — list of PeerInfo entries
//!
//! Canonical CBOR key order (RFC 8949 §4.2.1, bytewise on encoded keys):
//!
//!   PeerAskPayload  : limit < intent_filter
//!   PeerTellPayload : peers
//!   PeerInfo        : address < intents < endpoints < last_seen

use crate::cbor::{self, CborReader, MapEntry};
use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerAskPayload {
    /// Limit on number of peers the responder should return.
    pub limit: u64,
    /// Optional intent filter; `None` = any.
    pub intent_filter: Option<u8>,
}

impl PeerAskPayload {
    pub fn encode(&self) -> Vec<u8> {
        let entries = [
            MapEntry {
                key: cbor::text("limit"),
                value: cbor::uint(self.limit),
            },
            MapEntry {
                key: cbor::text("intent_filter"),
                value: match self.intent_filter {
                    Some(i) => cbor::uint(i as u64),
                    None => cbor::null(),
                },
            },
        ];
        cbor::encode_map(&entries)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = CborReader::new(bytes);
        let n = r.read_map_header()?;
        if n != 2 {
            return Err(Error::CborDecode(format!(
                "PeerAsk expected 2 keys, got {n}"
            )));
        }
        if r.read_text()? != "limit" {
            return Err(Error::CborNotCanonical("expected 'limit' first"));
        }
        let limit = r.read_u64()?;
        if r.read_text()? != "intent_filter" {
            return Err(Error::CborNotCanonical("expected 'intent_filter' second"));
        }
        let peek = *r
            .remaining()
            .first()
            .ok_or_else(|| Error::CborDecode("missing intent_filter".into()))?;
        let intent_filter = if peek == 0xF6 {
            r.read_bytes_or_null()?;
            None
        } else {
            let v = r.read_u64()?;
            if v > 0xFF {
                return Err(Error::CborDecode(format!("intent out of u8: {v}")));
            }
            Some(v as u8)
        };
        Ok(Self {
            limit,
            intent_filter,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerInfo {
    pub address: [u8; 32],
    /// Sorted list of accepted intents (Intent::from_u8). Sorted bytewise
    /// for canonical encoding.
    pub intents: Vec<u8>,
    /// Network endpoints — host:port strings. Sorted lex.
    pub endpoints: Vec<String>,
    /// Unix seconds when this entry was last observed alive.
    pub last_seen: u64,
}

impl PeerInfo {
    pub fn encode(&self) -> Vec<u8> {
        let entries = [
            MapEntry {
                key: cbor::text("address"),
                value: cbor::bytes(&self.address),
            },
            MapEntry {
                key: cbor::text("intents"),
                value: encode_u8_array(&self.intents),
            },
            MapEntry {
                key: cbor::text("endpoints"),
                value: encode_text_array(&self.endpoints),
            },
            MapEntry {
                key: cbor::text("last_seen"),
                value: cbor::uint(self.last_seen),
            },
        ];
        cbor::encode_map(&entries)
    }

    pub fn decode_from(r: &mut CborReader<'_>) -> Result<Self> {
        let n = r.read_map_header()?;
        if n != 4 {
            return Err(Error::CborDecode(format!(
                "PeerInfo expected 4 keys, got {n}"
            )));
        }
        let expected = ["address", "intents", "endpoints", "last_seen"];
        let mut address = None;
        let mut intents = None;
        let mut endpoints = None;
        let mut last_seen = None;
        for e in expected {
            let k = r.read_text()?;
            if k != e {
                return Err(Error::CborNotCanonical(
                    "PeerInfo keys not in canonical order",
                ));
            }
            match e {
                "address" => {
                    let b = r.read_bytes()?;
                    if b.len() != 32 {
                        return Err(Error::BadFieldLength {
                            field: "address",
                            expected: 32,
                            got: b.len(),
                        });
                    }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(b);
                    address = Some(arr);
                }
                "intents" => intents = Some(decode_u8_array(r)?),
                "endpoints" => endpoints = Some(decode_text_array(r)?),
                "last_seen" => last_seen = Some(r.read_u64()?),
                _ => unreachable!(),
            }
        }
        Ok(Self {
            address: address.ok_or(Error::Invariant("missing address"))?,
            intents: intents.ok_or(Error::Invariant("missing intents"))?,
            endpoints: endpoints.ok_or(Error::Invariant("missing endpoints"))?,
            last_seen: last_seen.ok_or(Error::Invariant("missing last_seen"))?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerTellPayload {
    pub peers: Vec<PeerInfo>,
}

impl PeerTellPayload {
    pub fn encode(&self) -> Vec<u8> {
        let mut header = cbor::CborWriter::new();
        header.write_array_header(self.peers.len());
        let mut peers_bytes = header.into_bytes();
        for p in &self.peers {
            peers_bytes.extend_from_slice(&p.encode());
        }
        let entries = [MapEntry {
            key: cbor::text("peers"),
            value: peers_bytes,
        }];
        cbor::encode_map(&entries)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = CborReader::new(bytes);
        let n = r.read_map_header()?;
        if n != 1 {
            return Err(Error::CborDecode(format!(
                "PeerTell expected 1 key, got {n}"
            )));
        }
        if r.read_text()? != "peers" {
            return Err(Error::CborNotCanonical("expected 'peers'"));
        }
        let cnt = r.read_array_header()?;
        let mut peers = Vec::with_capacity(cnt);
        for _ in 0..cnt {
            peers.push(PeerInfo::decode_from(&mut r)?);
        }
        Ok(Self { peers })
    }
}

fn encode_u8_array(items: &[u8]) -> Vec<u8> {
    let mut w = cbor::CborWriter::new();
    w.write_array_header(items.len());
    for b in items {
        w.write_u64(*b as u64);
    }
    w.into_bytes()
}

fn decode_u8_array(r: &mut CborReader<'_>) -> Result<Vec<u8>> {
    let n = r.read_array_header()?;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let v = r.read_u64()?;
        if v > 0xFF {
            return Err(Error::CborDecode(format!("intent out of u8: {v}")));
        }
        out.push(v as u8);
    }
    Ok(out)
}

fn encode_text_array(items: &[String]) -> Vec<u8> {
    let mut w = cbor::CborWriter::new();
    w.write_array_header(items.len());
    for s in items {
        w.write_text(s);
    }
    w.into_bytes()
}

fn decode_text_array(r: &mut CborReader<'_>) -> Result<Vec<String>> {
    let n = r.read_array_header()?;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(r.read_text()?.to_owned());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_ask_roundtrip() {
        let p = PeerAskPayload {
            limit: 50,
            intent_filter: Some(1),
        };
        let bytes = p.encode();
        let decoded = PeerAskPayload::decode(&bytes).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn peer_ask_no_filter_roundtrip() {
        let p = PeerAskPayload {
            limit: 10,
            intent_filter: None,
        };
        let bytes = p.encode();
        let decoded = PeerAskPayload::decode(&bytes).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn peer_tell_empty() {
        let p = PeerTellPayload { peers: vec![] };
        let bytes = p.encode();
        let decoded = PeerTellPayload::decode(&bytes).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn peer_tell_with_two_peers() {
        let p = PeerTellPayload {
            peers: vec![
                PeerInfo {
                    address: [1u8; 32],
                    intents: vec![1, 2, 3],
                    endpoints: vec!["10.0.0.1:4242".into(), "[2001:db8::1]:4242".into()],
                    last_seen: 1700000000,
                },
                PeerInfo {
                    address: [9u8; 32],
                    intents: vec![1],
                    endpoints: vec!["192.168.1.5:4242".into()],
                    last_seen: 1700000100,
                },
            ],
        };
        let bytes = p.encode();
        let decoded = PeerTellPayload::decode(&bytes).unwrap();
        assert_eq!(decoded, p);
    }
}
