//! Handshake payload codecs — Appendix A range 0x10–0x12 (§4.3).
//!
//! Three payload types:
//!
//!   * 0x10 Hello       — initiator → responder
//!   * 0x11 HelloBack   — responder → initiator
//!   * 0x12 Confirm     — initiator → responder (transcript MAC)
//!
//! Canonical CBOR key orders (RFC 8949 §4.2.1, bytewise on encoded keys):
//!
//!   HelloPayload     : v_max < v_min < intent < eph_pub < extensions < capabilities
//!   HelloBackPayload : v < accept < reason < eph_pub < extensions < capabilities
//!   ConfirmPayload   : proof

use std::collections::BTreeMap;

use crate::cbor::{self, CborReader, MapEntry};
use crate::error::{Error, Result};

/// Intent declared at handshake time (§4.4). Constants match the spec.
pub mod intent {
    pub const DIRECT: u8 = 1;
    pub const STORAGE: u8 = 2;
    pub const GOSSIP: u8 = 3;
    pub const VERSE: u8 = 4;
    pub const PUBLIC_LAYER: u8 = 5;
}

/// Length of an X25519 public key in bytes.
pub const EPH_PUB_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloPayload {
    pub v_max: u64,
    pub v_min: u64,
    pub extensions: Vec<String>,
    pub eph_pub: [u8; EPH_PUB_LEN],
    pub intent: u8,
    /// Open-ended limits map. v1 keeps values as uints; future versions can
    /// extend without a major bump.
    pub capabilities: BTreeMap<String, u64>,
}

impl HelloPayload {
    pub fn encode(&self) -> Vec<u8> {
        let entries = [
            MapEntry {
                key: cbor::text("v_max"),
                value: cbor::uint(self.v_max),
            },
            MapEntry {
                key: cbor::text("v_min"),
                value: cbor::uint(self.v_min),
            },
            MapEntry {
                key: cbor::text("intent"),
                value: cbor::uint(self.intent as u64),
            },
            MapEntry {
                key: cbor::text("eph_pub"),
                value: cbor::bytes(&self.eph_pub),
            },
            MapEntry {
                key: cbor::text("extensions"),
                value: encode_array_of_text(&self.extensions),
            },
            MapEntry {
                key: cbor::text("capabilities"),
                value: encode_capabilities(&self.capabilities),
            },
        ];
        cbor::encode_map(&entries)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = CborReader::new(bytes);
        let n = r.read_map_header()?;
        if n != 6 {
            return Err(Error::CborDecode(format!(
                "HelloPayload expected 6 keys, got {n}"
            )));
        }
        let expected = [
            "v_max",
            "v_min",
            "intent",
            "eph_pub",
            "extensions",
            "capabilities",
        ];
        let mut v_max = None;
        let mut v_min = None;
        let mut intent = None;
        let mut eph_pub = None;
        let mut extensions = None;
        let mut capabilities = None;

        for e in expected {
            let k = r.read_text()?;
            if k != e {
                return Err(Error::CborNotCanonical(
                    "HelloPayload keys not in canonical order",
                ));
            }
            match e {
                "v_max" => v_max = Some(r.read_u64()?),
                "v_min" => v_min = Some(r.read_u64()?),
                "intent" => {
                    let i = r.read_u64()?;
                    if i > 0xFF {
                        return Err(Error::CborDecode(format!("intent out of u8 range: {i}")));
                    }
                    intent = Some(i as u8);
                }
                "eph_pub" => eph_pub = Some(read_fixed_bytes(&mut r, "eph_pub", EPH_PUB_LEN)?),
                "extensions" => extensions = Some(decode_array_of_text(&mut r)?),
                "capabilities" => capabilities = Some(decode_capabilities(&mut r)?),
                _ => unreachable!(),
            }
        }
        if !r.at_end() {
            return Err(Error::CborDecode(
                "trailing bytes after HelloPayload".into(),
            ));
        }
        let eph_pub_bytes = eph_pub.ok_or(Error::Invariant("missing eph_pub"))?;
        let mut eph_pub_arr = [0u8; EPH_PUB_LEN];
        eph_pub_arr.copy_from_slice(eph_pub_bytes);
        Ok(HelloPayload {
            v_max: v_max.ok_or(Error::Invariant("missing v_max"))?,
            v_min: v_min.ok_or(Error::Invariant("missing v_min"))?,
            intent: intent.ok_or(Error::Invariant("missing intent"))?,
            eph_pub: eph_pub_arr,
            extensions: extensions.ok_or(Error::Invariant("missing extensions"))?,
            capabilities: capabilities.ok_or(Error::Invariant("missing capabilities"))?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloBackPayload {
    pub v: u64,
    pub accept: bool,
    pub reason: Option<String>,
    pub eph_pub: [u8; EPH_PUB_LEN],
    pub extensions: Vec<String>,
    pub capabilities: BTreeMap<String, u64>,
}

impl HelloBackPayload {
    pub fn encode(&self) -> Vec<u8> {
        let entries = [
            MapEntry {
                key: cbor::text("v"),
                value: cbor::uint(self.v),
            },
            MapEntry {
                key: cbor::text("accept"),
                value: cbor::boolean(self.accept),
            },
            MapEntry {
                key: cbor::text("reason"),
                value: match &self.reason {
                    Some(s) => cbor::text(s),
                    None => cbor::null(),
                },
            },
            MapEntry {
                key: cbor::text("eph_pub"),
                value: cbor::bytes(&self.eph_pub),
            },
            MapEntry {
                key: cbor::text("extensions"),
                value: encode_array_of_text(&self.extensions),
            },
            MapEntry {
                key: cbor::text("capabilities"),
                value: encode_capabilities(&self.capabilities),
            },
        ];
        cbor::encode_map(&entries)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = CborReader::new(bytes);
        let n = r.read_map_header()?;
        if n != 6 {
            return Err(Error::CborDecode(format!(
                "HelloBackPayload expected 6 keys, got {n}"
            )));
        }
        let expected = [
            "v",
            "accept",
            "reason",
            "eph_pub",
            "extensions",
            "capabilities",
        ];
        let mut v = None;
        let mut accept = None;
        let mut reason: Option<Option<String>> = None;
        let mut eph_pub = None;
        let mut extensions = None;
        let mut capabilities = None;

        for e in expected {
            let k = r.read_text()?;
            if k != e {
                return Err(Error::CborNotCanonical(
                    "HelloBackPayload keys not in canonical order",
                ));
            }
            match e {
                "v" => v = Some(r.read_u64()?),
                "accept" => accept = Some(r.read_bool()?),
                "reason" => {
                    // Either a text string or nil.
                    let peek = *r
                        .remaining()
                        .first()
                        .ok_or_else(|| Error::CborDecode("missing reason".into()))?;
                    if peek == 0xF6 {
                        // null
                        r.read_bytes_or_null()?;
                        reason = Some(None);
                    } else {
                        reason = Some(Some(r.read_text()?.to_owned()));
                    }
                }
                "eph_pub" => eph_pub = Some(read_fixed_bytes(&mut r, "eph_pub", EPH_PUB_LEN)?),
                "extensions" => extensions = Some(decode_array_of_text(&mut r)?),
                "capabilities" => capabilities = Some(decode_capabilities(&mut r)?),
                _ => unreachable!(),
            }
        }
        if !r.at_end() {
            return Err(Error::CborDecode(
                "trailing bytes after HelloBackPayload".into(),
            ));
        }
        let eph_pub_bytes = eph_pub.ok_or(Error::Invariant("missing eph_pub"))?;
        let mut eph_pub_arr = [0u8; EPH_PUB_LEN];
        eph_pub_arr.copy_from_slice(eph_pub_bytes);
        Ok(HelloBackPayload {
            v: v.ok_or(Error::Invariant("missing v"))?,
            accept: accept.ok_or(Error::Invariant("missing accept"))?,
            reason: reason.ok_or(Error::Invariant("missing reason"))?,
            eph_pub: eph_pub_arr,
            extensions: extensions.ok_or(Error::Invariant("missing extensions"))?,
            capabilities: capabilities.ok_or(Error::Invariant("missing capabilities"))?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmPayload {
    pub proof: [u8; 32],
}

impl ConfirmPayload {
    pub fn encode(&self) -> Vec<u8> {
        let entries = [MapEntry {
            key: cbor::text("proof"),
            value: cbor::bytes(&self.proof),
        }];
        cbor::encode_map(&entries)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = CborReader::new(bytes);
        let n = r.read_map_header()?;
        if n != 1 {
            return Err(Error::CborDecode(format!(
                "ConfirmPayload expected 1 key, got {n}"
            )));
        }
        if r.read_text()? != "proof" {
            return Err(Error::CborNotCanonical("ConfirmPayload expects 'proof'"));
        }
        let proof_bytes = r.read_bytes()?;
        if proof_bytes.len() != 32 {
            return Err(Error::BadFieldLength {
                field: "proof",
                expected: 32,
                got: proof_bytes.len(),
            });
        }
        let mut proof = [0u8; 32];
        proof.copy_from_slice(proof_bytes);
        if !r.at_end() {
            return Err(Error::CborDecode("trailing bytes after Confirm".into()));
        }
        Ok(Self { proof })
    }
}

// =========================================================================
// helpers
// =========================================================================

fn encode_array_of_text(items: &[String]) -> Vec<u8> {
    let mut w = cbor::CborWriter::new();
    w.write_array_header(items.len());
    for s in items {
        w.write_text(s);
    }
    w.into_bytes()
}

fn decode_array_of_text(r: &mut CborReader<'_>) -> Result<Vec<String>> {
    let n = r.read_array_header()?;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(r.read_text()?.to_owned());
    }
    Ok(out)
}

fn encode_capabilities(map: &BTreeMap<String, u64>) -> Vec<u8> {
    let mut entries: Vec<MapEntry> = map
        .iter()
        .map(|(k, v)| MapEntry {
            key: cbor::text(k),
            value: cbor::uint(*v),
        })
        .collect();
    // Sort by encoded key bytes (canonical CBOR ordering — different from
    // BTreeMap's Rust-string ordering for keys of different lengths).
    entries.sort_by(|a, b| a.key.cmp(&b.key));
    cbor::encode_map(&entries)
}

fn decode_capabilities(r: &mut CborReader<'_>) -> Result<BTreeMap<String, u64>> {
    let n = r.read_map_header()?;
    let mut out = BTreeMap::new();
    let mut last_key_bytes: Option<Vec<u8>> = None;
    for _ in 0..n {
        let key_start = r.position();
        let k = r.read_text()?.to_owned();
        let key_bytes = r.buf[key_start..r.position()].to_vec();
        if let Some(prev) = &last_key_bytes
            && prev >= &key_bytes
        {
            return Err(Error::CborNotCanonical(
                "capabilities keys not in canonical order",
            ));
        }
        last_key_bytes = Some(key_bytes);
        let v = r.read_u64()?;
        out.insert(k, v);
    }
    Ok(out)
}

fn read_fixed_bytes<'a>(
    r: &mut CborReader<'a>,
    field: &'static str,
    expected: usize,
) -> Result<&'a [u8]> {
    let b = r.read_bytes()?;
    if b.len() != expected {
        return Err(Error::BadFieldLength {
            field,
            expected,
            got: b.len(),
        });
    }
    Ok(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_roundtrip() {
        let mut caps = BTreeMap::new();
        caps.insert("max_message_rate".to_owned(), 100);
        caps.insert("max_object_size".to_owned(), 67_108_864);
        let p = HelloPayload {
            v_max: 1,
            v_min: 1,
            extensions: vec!["ext-a".to_owned(), "ext-b".to_owned()],
            eph_pub: [0xAB; EPH_PUB_LEN],
            intent: intent::DIRECT,
            capabilities: caps,
        };
        let bytes = p.encode();
        let decoded = HelloPayload::decode(&bytes).unwrap();
        assert_eq!(decoded, p);
        // 6-key map header
        assert_eq!(bytes[0], 0xA6);
    }

    #[test]
    fn helloback_accept_roundtrip() {
        let p = HelloBackPayload {
            v: 1,
            accept: true,
            reason: None,
            eph_pub: [0xCC; EPH_PUB_LEN],
            extensions: vec![],
            capabilities: BTreeMap::new(),
        };
        let bytes = p.encode();
        let decoded = HelloBackPayload::decode(&bytes).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn helloback_decline_with_reason() {
        let p = HelloBackPayload {
            v: 1,
            accept: false,
            reason: Some("version-incompatible".to_owned()),
            eph_pub: [0u8; EPH_PUB_LEN],
            extensions: vec![],
            capabilities: BTreeMap::new(),
        };
        let bytes = p.encode();
        let decoded = HelloBackPayload::decode(&bytes).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn confirm_roundtrip() {
        let p = ConfirmPayload { proof: [9u8; 32] };
        let bytes = p.encode();
        let decoded = ConfirmPayload::decode(&bytes).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn capabilities_keys_must_be_in_canonical_order() {
        // Construct bytes with two capabilities keys in WRONG canonical order:
        // "z" then "a". Bytewise, "a"=0x61, "z"=0x7a; "a" < "z".
        let mut bytes = vec![0xA2u8]; // 2-entry map
        bytes.push(0x61); // text key 1 char
        bytes.push(b'z');
        bytes.push(0x01); // uint 1
        bytes.push(0x61);
        bytes.push(b'a');
        bytes.push(0x02);
        let mut r = CborReader::new(&bytes);
        let err = decode_capabilities(&mut r).unwrap_err();
        assert!(matches!(err, Error::CborNotCanonical(_)), "got {err:?}");
    }
}
