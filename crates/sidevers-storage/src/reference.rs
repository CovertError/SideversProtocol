//! Reference type (protocol spec §5.3).
//!
//! A reference is what travels in messages, verses, and posts to point at
//! a content-addressed object. It includes the BLAKE3 hash, the size, an
//! advisory MIME type, optional hints (addresses of nodes likely to have
//! the bytes), and optional dependency references.
//!
//! Canonical CBOR key order (RFC 8949 §4.2.1, bytewise on encoded keys):
//!
//!   deps  < hash < size < type < hints

use sidevers_core::cbor::{self, CborReader, MapEntry};
use sidevers_core::error::{Error as CoreError, Result as CoreResult};

use crate::object::ADDRESS_LEN;

/// Default max depth for a `Reference`'s dependency walk.
pub const DEFAULT_DEP_DEPTH_LIMIT: usize = 64;

/// A reference points at one content-addressed object plus optional
/// dependencies and hints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    pub hash: [u8; ADDRESS_LEN],
    pub size: u64,
    pub mime: String,
    pub hints: Vec<[u8; 32]>,
    pub deps: Vec<Reference>,
}

impl Reference {
    pub fn new(hash: [u8; ADDRESS_LEN], size: u64, mime: impl Into<String>) -> Self {
        Self {
            hash,
            size,
            mime: mime.into(),
            hints: Vec::new(),
            deps: Vec::new(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let entries = [
            MapEntry {
                key: cbor::text("deps"),
                value: encode_dep_array(&self.deps),
            },
            MapEntry {
                key: cbor::text("hash"),
                value: cbor::bytes(&self.hash),
            },
            MapEntry {
                key: cbor::text("size"),
                value: cbor::uint(self.size),
            },
            MapEntry {
                key: cbor::text("type"),
                value: cbor::text(&self.mime),
            },
            MapEntry {
                key: cbor::text("hints"),
                value: encode_hints_array(&self.hints),
            },
        ];
        cbor::encode_map(&entries)
    }

    pub fn decode(bytes: &[u8]) -> CoreResult<Self> {
        let mut r = CborReader::new(bytes);
        Self::decode_inner(&mut r, 0)
    }

    fn decode_inner(r: &mut CborReader<'_>, depth: usize) -> CoreResult<Self> {
        if depth > DEFAULT_DEP_DEPTH_LIMIT {
            return Err(CoreError::Invariant("reference depth limit exceeded"));
        }
        let n = r.read_map_header()?;
        if n != 5 {
            return Err(CoreError::CborDecode(format!(
                "Reference expected 5 keys, got {n}"
            )));
        }
        let expected = ["deps", "hash", "size", "type", "hints"];
        let mut deps = None;
        let mut hash = None;
        let mut size = None;
        let mut mime = None;
        let mut hints = None;

        for e in expected {
            let k = r.read_text()?;
            if k != e {
                return Err(CoreError::CborNotCanonical(
                    "Reference keys not in canonical order",
                ));
            }
            match e {
                "deps" => deps = Some(decode_dep_array(r, depth + 1)?),
                "hash" => {
                    let b = r.read_bytes()?;
                    if b.len() != ADDRESS_LEN {
                        return Err(CoreError::BadFieldLength {
                            field: "hash",
                            expected: ADDRESS_LEN,
                            got: b.len(),
                        });
                    }
                    let mut arr = [0u8; ADDRESS_LEN];
                    arr.copy_from_slice(b);
                    hash = Some(arr);
                }
                "size" => size = Some(r.read_u64()?),
                "type" => mime = Some(r.read_text()?.to_owned()),
                "hints" => hints = Some(decode_hints_array(r)?),
                _ => unreachable!(),
            }
        }
        Ok(Self {
            hash: hash.ok_or(CoreError::Invariant("missing hash"))?,
            size: size.ok_or(CoreError::Invariant("missing size"))?,
            mime: mime.ok_or(CoreError::Invariant("missing type"))?,
            hints: hints.ok_or(CoreError::Invariant("missing hints"))?,
            deps: deps.ok_or(CoreError::Invariant("missing deps"))?,
        })
    }
}

fn encode_hints_array(hints: &[[u8; 32]]) -> Vec<u8> {
    let mut w = cbor::CborWriter::new();
    w.write_array_header(hints.len());
    for h in hints {
        w.write_bytes(h);
    }
    w.into_bytes()
}

fn decode_hints_array(r: &mut CborReader<'_>) -> CoreResult<Vec<[u8; 32]>> {
    let n = r.read_array_header()?;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let b = r.read_bytes()?;
        if b.len() != 32 {
            return Err(CoreError::BadFieldLength {
                field: "hint",
                expected: 32,
                got: b.len(),
            });
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(b);
        out.push(arr);
    }
    Ok(out)
}

fn encode_dep_array(deps: &[Reference]) -> Vec<u8> {
    let mut w = cbor::CborWriter::new();
    w.write_array_header(deps.len());
    let mut out = w.into_bytes();
    for d in deps {
        // Each Reference encoding is already canonical CBOR; append verbatim.
        out.extend_from_slice(&d.encode());
    }
    out
}

fn decode_dep_array(r: &mut CborReader<'_>, depth: usize) -> CoreResult<Vec<Reference>> {
    let n = r.read_array_header()?;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(Reference::decode_inner(r, depth)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn round_trip_leaf_reference() {
        let r = Reference {
            hash: [0x42; ADDRESS_LEN],
            size: 1024,
            mime: "image/jpeg".into(),
            hints: vec![[1u8; 32], [2u8; 32]],
            deps: vec![],
        };
        let bytes = r.encode();
        let decoded = Reference::decode(&bytes).unwrap();
        assert_eq!(decoded, r);
    }

    #[test]
    fn round_trip_reference_with_deps() {
        let leaf1 = Reference::new([1u8; ADDRESS_LEN], 100, "text/plain");
        let leaf2 = Reference::new([2u8; ADDRESS_LEN], 200, "image/png");
        let root = Reference {
            hash: [9u8; ADDRESS_LEN],
            size: 500,
            mime: "application/cbor".into(),
            hints: vec![],
            deps: vec![leaf1, leaf2],
        };
        let bytes = root.encode();
        let decoded = Reference::decode(&bytes).unwrap();
        assert_eq!(decoded, root);
    }

    #[test]
    fn depth_limit_blocks_attacker_bombs() {
        // Build a deeply-nested reference chain and ensure decode caps it.
        let mut r = Reference::new([0u8; ADDRESS_LEN], 1, "x");
        for _ in 0..(DEFAULT_DEP_DEPTH_LIMIT + 2) {
            r = Reference {
                hash: [0u8; ADDRESS_LEN],
                size: 1,
                mime: "x".into(),
                hints: vec![],
                deps: vec![r],
            };
        }
        let bytes = r.encode();
        let err = Reference::decode(&bytes).unwrap_err();
        assert!(matches!(err, CoreError::Invariant(_)), "got {err:?}");
    }
}
