//! Storage protocol message codecs (Appendix A range 0x30–0x35, spec §5.4–§5.6).
//!
//! Six payload types:
//!
//!   * 0x30 StorageGet      — `{ hash, range? }`
//!   * 0x31 StorageHave     — `{ hash, bytes, final }`
//!   * 0x32 StorageMiss     — `{ hash, hints }`
//!   * 0x33 StorageOffer    — `{ reference }`
//!   * 0x34 StorageWant     — `{ hash, want }`
//!   * 0x35 StorageRetract  — `{ hash }`

use sidevers_core::cbor::{self, CborReader, MapEntry};
use sidevers_core::error::{Error as CoreError, Result as CoreResult};
use sidevers_storage::Reference;
use sidevers_storage::object::ADDRESS_LEN;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageGetPayload {
    pub hash: [u8; ADDRESS_LEN],
    pub range: Option<ByteRange>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteRange {
    pub start: u64,
    pub end: u64,
}

impl StorageGetPayload {
    /// Canonical key order: "hash" (0x64 68 61 73 68) < "range" (0x65 72 ...).
    pub fn encode(&self) -> Vec<u8> {
        let entries = [
            MapEntry {
                key: cbor::text("hash"),
                value: cbor::bytes(&self.hash),
            },
            MapEntry {
                key: cbor::text("range"),
                value: match &self.range {
                    Some(r) => encode_range(r),
                    None => cbor::null(),
                },
            },
        ];
        cbor::encode_map(&entries)
    }

    pub fn decode(bytes: &[u8]) -> CoreResult<Self> {
        let mut r = CborReader::new(bytes);
        let n = r.read_map_header()?;
        if n != 2 {
            return Err(CoreError::CborDecode(format!(
                "StorageGet expected 2 keys, got {n}"
            )));
        }
        if r.read_text()? != "hash" {
            return Err(CoreError::CborNotCanonical("expected 'hash' first"));
        }
        let h = r.read_bytes()?;
        if h.len() != ADDRESS_LEN {
            return Err(CoreError::BadFieldLength {
                field: "hash",
                expected: ADDRESS_LEN,
                got: h.len(),
            });
        }
        let mut hash = [0u8; ADDRESS_LEN];
        hash.copy_from_slice(h);
        if r.read_text()? != "range" {
            return Err(CoreError::CborNotCanonical("expected 'range' second"));
        }
        let range = decode_optional_range(&mut r)?;
        Ok(Self { hash, range })
    }
}

fn encode_range(r: &ByteRange) -> Vec<u8> {
    // Sub-map keys: "end" < "start" by bytewise sort.
    let entries = [
        MapEntry {
            key: cbor::text("end"),
            value: cbor::uint(r.end),
        },
        MapEntry {
            key: cbor::text("start"),
            value: cbor::uint(r.start),
        },
    ];
    cbor::encode_map(&entries)
}

fn decode_optional_range(r: &mut CborReader<'_>) -> CoreResult<Option<ByteRange>> {
    let peek = *r
        .remaining()
        .first()
        .ok_or_else(|| CoreError::CborDecode("missing range".into()))?;
    if peek == 0xF6 {
        r.read_bytes_or_null()?;
        return Ok(None);
    }
    let n = r.read_map_header()?;
    if n != 2 {
        return Err(CoreError::CborDecode(format!(
            "range expected 2 keys, got {n}"
        )));
    }
    if r.read_text()? != "end" {
        return Err(CoreError::CborNotCanonical("range expects 'end' first"));
    }
    let end = r.read_u64()?;
    if r.read_text()? != "start" {
        return Err(CoreError::CborNotCanonical("range expects 'start' second"));
    }
    let start = r.read_u64()?;
    Ok(Some(ByteRange { start, end }))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageHavePayload {
    pub hash: [u8; ADDRESS_LEN],
    pub bytes: Vec<u8>,
    pub final_: bool,
}

impl StorageHavePayload {
    /// Canonical key order: "bytes" (0x65 62 ...) < "final" (0x65 66 ...) < "hash" (0x64 68 ...).
    /// Sorted bytewise: "hash" (0x64...) < "bytes" (0x65 62...) < "final" (0x65 66...).
    pub fn encode(&self) -> Vec<u8> {
        let entries = [
            MapEntry {
                key: cbor::text("hash"),
                value: cbor::bytes(&self.hash),
            },
            MapEntry {
                key: cbor::text("bytes"),
                value: cbor::bytes(&self.bytes),
            },
            MapEntry {
                key: cbor::text("final"),
                value: cbor::boolean(self.final_),
            },
        ];
        cbor::encode_map(&entries)
    }

    pub fn decode(bytes_in: &[u8]) -> CoreResult<Self> {
        let mut r = CborReader::new(bytes_in);
        let n = r.read_map_header()?;
        if n != 3 {
            return Err(CoreError::CborDecode(format!(
                "StorageHave expected 3 keys, got {n}"
            )));
        }
        if r.read_text()? != "hash" {
            return Err(CoreError::CborNotCanonical("expected 'hash' first"));
        }
        let h = r.read_bytes()?;
        if h.len() != ADDRESS_LEN {
            return Err(CoreError::BadFieldLength {
                field: "hash",
                expected: ADDRESS_LEN,
                got: h.len(),
            });
        }
        let mut hash = [0u8; ADDRESS_LEN];
        hash.copy_from_slice(h);
        if r.read_text()? != "bytes" {
            return Err(CoreError::CborNotCanonical("expected 'bytes' second"));
        }
        let body = r.read_bytes()?.to_vec();
        if r.read_text()? != "final" {
            return Err(CoreError::CborNotCanonical("expected 'final' third"));
        }
        let final_ = r.read_bool()?;
        Ok(Self {
            hash,
            bytes: body,
            final_,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageMissPayload {
    pub hash: [u8; ADDRESS_LEN],
    pub hints: Vec<[u8; 32]>,
}

impl StorageMissPayload {
    pub fn encode(&self) -> Vec<u8> {
        let mut hints_buf = cbor::CborWriter::new();
        hints_buf.write_array_header(self.hints.len());
        let mut hints_bytes = hints_buf.into_bytes();
        for h in &self.hints {
            hints_bytes.extend_from_slice(&cbor::bytes(h));
        }
        let entries = [
            MapEntry {
                key: cbor::text("hash"),
                value: cbor::bytes(&self.hash),
            },
            MapEntry {
                key: cbor::text("hints"),
                value: hints_bytes,
            },
        ];
        cbor::encode_map(&entries)
    }

    pub fn decode(bytes: &[u8]) -> CoreResult<Self> {
        let mut r = CborReader::new(bytes);
        let n = r.read_map_header()?;
        if n != 2 {
            return Err(CoreError::CborDecode(format!(
                "StorageMiss expected 2 keys, got {n}"
            )));
        }
        if r.read_text()? != "hash" {
            return Err(CoreError::CborNotCanonical("expected 'hash' first"));
        }
        let h = r.read_bytes()?;
        if h.len() != ADDRESS_LEN {
            return Err(CoreError::BadFieldLength {
                field: "hash",
                expected: ADDRESS_LEN,
                got: h.len(),
            });
        }
        let mut hash = [0u8; ADDRESS_LEN];
        hash.copy_from_slice(h);
        if r.read_text()? != "hints" {
            return Err(CoreError::CborNotCanonical("expected 'hints' second"));
        }
        let cnt = r.read_array_header()?;
        let mut hints = Vec::with_capacity(cnt);
        for _ in 0..cnt {
            let hb = r.read_bytes()?;
            if hb.len() != 32 {
                return Err(CoreError::BadFieldLength {
                    field: "hint",
                    expected: 32,
                    got: hb.len(),
                });
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(hb);
            hints.push(arr);
        }
        Ok(Self { hash, hints })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageOfferPayload {
    pub reference: Reference,
}

impl StorageOfferPayload {
    pub fn encode(&self) -> Vec<u8> {
        let entries = [MapEntry {
            key: cbor::text("reference"),
            value: self.reference.encode(),
        }];
        cbor::encode_map(&entries)
    }

    pub fn decode(bytes: &[u8]) -> CoreResult<Self> {
        let mut r = CborReader::new(bytes);
        let n = r.read_map_header()?;
        if n != 1 {
            return Err(CoreError::CborDecode(format!(
                "StorageOffer expected 1 key, got {n}"
            )));
        }
        if r.read_text()? != "reference" {
            return Err(CoreError::CborNotCanonical("expected 'reference'"));
        }
        // Consume the embedded reference's bytes.
        let start = r.position();
        // Use Reference::decode on the remaining slice.
        let remaining_after_key = &bytes[start..];
        let reference = Reference::decode(remaining_after_key)?;
        Ok(Self { reference })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageWantPayload {
    pub hash: [u8; ADDRESS_LEN],
    pub want: bool,
}

impl StorageWantPayload {
    pub fn encode(&self) -> Vec<u8> {
        // Canonical: "hash" < "want".
        let entries = [
            MapEntry {
                key: cbor::text("hash"),
                value: cbor::bytes(&self.hash),
            },
            MapEntry {
                key: cbor::text("want"),
                value: cbor::boolean(self.want),
            },
        ];
        cbor::encode_map(&entries)
    }

    pub fn decode(bytes: &[u8]) -> CoreResult<Self> {
        let mut r = CborReader::new(bytes);
        let n = r.read_map_header()?;
        if n != 2 {
            return Err(CoreError::CborDecode(format!(
                "StorageWant expected 2 keys, got {n}"
            )));
        }
        if r.read_text()? != "hash" {
            return Err(CoreError::CborNotCanonical("expected 'hash' first"));
        }
        let h = r.read_bytes()?;
        if h.len() != ADDRESS_LEN {
            return Err(CoreError::BadFieldLength {
                field: "hash",
                expected: ADDRESS_LEN,
                got: h.len(),
            });
        }
        let mut hash = [0u8; ADDRESS_LEN];
        hash.copy_from_slice(h);
        if r.read_text()? != "want" {
            return Err(CoreError::CborNotCanonical("expected 'want' second"));
        }
        let want = r.read_bool()?;
        Ok(Self { hash, want })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageRetractPayload {
    pub hash: [u8; ADDRESS_LEN],
}

impl StorageRetractPayload {
    pub fn encode(&self) -> Vec<u8> {
        let entries = [MapEntry {
            key: cbor::text("hash"),
            value: cbor::bytes(&self.hash),
        }];
        cbor::encode_map(&entries)
    }

    pub fn decode(bytes: &[u8]) -> CoreResult<Self> {
        let mut r = CborReader::new(bytes);
        let n = r.read_map_header()?;
        if n != 1 {
            return Err(CoreError::CborDecode(format!(
                "StorageRetract expected 1 key, got {n}"
            )));
        }
        if r.read_text()? != "hash" {
            return Err(CoreError::CborNotCanonical("expected 'hash'"));
        }
        let h = r.read_bytes()?;
        if h.len() != ADDRESS_LEN {
            return Err(CoreError::BadFieldLength {
                field: "hash",
                expected: ADDRESS_LEN,
                got: h.len(),
            });
        }
        let mut hash = [0u8; ADDRESS_LEN];
        hash.copy_from_slice(h);
        Ok(Self { hash })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn storage_get_roundtrip() {
        let p = StorageGetPayload {
            hash: [1u8; ADDRESS_LEN],
            range: Some(ByteRange { start: 0, end: 100 }),
        };
        let bytes = p.encode();
        let decoded = StorageGetPayload::decode(&bytes).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn storage_get_no_range_roundtrip() {
        let p = StorageGetPayload {
            hash: [9u8; ADDRESS_LEN],
            range: None,
        };
        let bytes = p.encode();
        let decoded = StorageGetPayload::decode(&bytes).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn storage_have_roundtrip() {
        let p = StorageHavePayload {
            hash: [3u8; ADDRESS_LEN],
            bytes: b"hello".to_vec(),
            final_: true,
        };
        let bytes = p.encode();
        let decoded = StorageHavePayload::decode(&bytes).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn storage_miss_roundtrip() {
        let p = StorageMissPayload {
            hash: [5u8; ADDRESS_LEN],
            hints: vec![[7u8; 32], [8u8; 32]],
        };
        let bytes = p.encode();
        let decoded = StorageMissPayload::decode(&bytes).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn storage_want_roundtrip() {
        let p = StorageWantPayload {
            hash: [1u8; ADDRESS_LEN],
            want: false,
        };
        let bytes = p.encode();
        let decoded = StorageWantPayload::decode(&bytes).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn storage_retract_roundtrip() {
        let p = StorageRetractPayload {
            hash: [2u8; ADDRESS_LEN],
        };
        let bytes = p.encode();
        let decoded = StorageRetractPayload::decode(&bytes).unwrap();
        assert_eq!(decoded, p);
    }
}
