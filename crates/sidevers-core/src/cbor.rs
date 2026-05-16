//! Deterministic CBOR encoding helpers (RFC 8949 §4.2.1).
//!
//! Spec §3.1 says: "a given message has exactly one valid byte representation
//! — same map key order, same integer encoding, same length prefixes."
//! Signatures are over bytes; one reordered key breaks verification silently.
//!
//! The strategy in this module:
//!
//!   * Provide a low-level writer (`CborWriter`) that emits the smallest valid
//!     CBOR head + length for each major type — never the long form when a
//!     short form fits.
//!   * Provide map-builder helpers that take *pre-encoded* key bytes and emit
//!     them in caller-supplied order. We do NOT sort here: callers know the
//!     canonical order for the structs they encode (e.g. envelope, payload)
//!     and have that order pinned in code so a regression is mechanical.
//!   * Provide a re-encode check that decodes our own output and re-encodes
//!     it, asserting byte-equality. Used in debug builds and tests.

use crate::error::{Error, Result};

/// Hard cap on the count argument returned by `read_array_header` /
/// `read_map_header`. A peer cannot trick a decoder into pre-allocating
/// `Vec::with_capacity(u32::MAX)` and OOM-ing the process — both readers
/// refuse counts above this ceiling. 1 million entries is generous (any
/// legitimate message stays well below ~1 thousand) and blocks the
/// adversarial case cheaply.
pub const MAX_CBOR_ENTRIES: usize = 1 << 20;

/// Maximum depth of nested CBOR maps/arrays that the recursive
/// `skip_value` helpers in `messages::*` will descend into. Stops a
/// crafted deeply-nested payload from blowing the parser stack. Real
/// messages do not nest more than ~3 levels.
pub const MAX_CBOR_SKIP_DEPTH: u8 = 32;

/// Major type bits, shifted into the high nibble of the initial byte.
const MT_UINT: u8 = 0 << 5;
const MT_NEGINT: u8 = 1 << 5;
const MT_BYTES: u8 = 2 << 5;
const MT_TEXT: u8 = 3 << 5;
const MT_ARRAY: u8 = 4 << 5;
const MT_MAP: u8 = 5 << 5;

/// CBOR "simple value" indicators we use.
const SIMPLE_FALSE: u8 = 0xF4;
const SIMPLE_TRUE: u8 = 0xF5;
const SIMPLE_NULL: u8 = 0xF6;

/// A buffer-backed CBOR writer that emits canonical, deterministic encoding.
///
/// Every length is emitted in shortest form (§4.2.1 of RFC 8949):
///   * `n` <= 23: inline in the head byte.
///   * `n` <= 0xFF: one-byte follow.
///   * `n` <= 0xFFFF: two-byte follow.
///   * `n` <= 0xFFFFFFFF: four-byte follow.
///   * otherwise: eight-byte follow.
#[derive(Default)]
pub struct CborWriter {
    pub(crate) buf: Vec<u8>,
}

impl CborWriter {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn with_capacity(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap),
        }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    fn write_head(&mut self, major: u8, value: u64) {
        if value <= 23 {
            self.buf.push(major | (value as u8));
        } else if value <= u8::MAX as u64 {
            self.buf.push(major | 24);
            self.buf.push(value as u8);
        } else if value <= u16::MAX as u64 {
            self.buf.push(major | 25);
            self.buf.extend_from_slice(&(value as u16).to_be_bytes());
        } else if value <= u32::MAX as u64 {
            self.buf.push(major | 26);
            self.buf.extend_from_slice(&(value as u32).to_be_bytes());
        } else {
            self.buf.push(major | 27);
            self.buf.extend_from_slice(&value.to_be_bytes());
        }
    }

    pub fn write_u64(&mut self, n: u64) {
        self.write_head(MT_UINT, n);
    }

    pub fn write_i64(&mut self, n: i64) {
        if n >= 0 {
            self.write_head(MT_UINT, n as u64);
        } else {
            // CBOR negint encoding: stored value is -1 - n.
            let v = (-(n + 1)) as u64;
            self.write_head(MT_NEGINT, v);
        }
    }

    pub fn write_bool(&mut self, b: bool) {
        self.buf.push(if b { SIMPLE_TRUE } else { SIMPLE_FALSE });
    }

    pub fn write_null(&mut self) {
        self.buf.push(SIMPLE_NULL);
    }

    pub fn write_bytes(&mut self, bytes: &[u8]) {
        self.write_head(MT_BYTES, bytes.len() as u64);
        self.buf.extend_from_slice(bytes);
    }

    pub fn write_text(&mut self, text: &str) {
        self.write_head(MT_TEXT, text.len() as u64);
        self.buf.extend_from_slice(text.as_bytes());
    }

    pub fn write_array_header(&mut self, len: usize) {
        self.write_head(MT_ARRAY, len as u64);
    }

    pub fn write_map_header(&mut self, len: usize) {
        self.write_head(MT_MAP, len as u64);
    }
}

/// One entry of a CBOR map: the key bytes (already encoded as CBOR) and the
/// value bytes (already encoded as CBOR).
pub struct MapEntry {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

/// Encode a CBOR map from a slice of `MapEntry` values.
///
/// Callers are responsible for supplying entries in canonical key order
/// (RFC 8949 §4.2.1 bytewise lexicographic order of encoded keys).
/// In debug builds, this function `debug_assert!`s that the entries are
/// already sorted in canonical order so a struct that gets a new field
/// inserted in the wrong place trips immediately in tests.
pub fn encode_map(entries: &[MapEntry]) -> Vec<u8> {
    debug_assert!(
        is_sorted_by_key(entries),
        "map entries not in canonical CBOR key order"
    );
    let mut w = CborWriter::with_capacity(
        entries
            .iter()
            .map(|e| e.key.len() + e.value.len())
            .sum::<usize>()
            + 4,
    );
    w.write_map_header(entries.len());
    for entry in entries {
        w.buf.extend_from_slice(&entry.key);
        w.buf.extend_from_slice(&entry.value);
    }
    w.into_bytes()
}

fn is_sorted_by_key(entries: &[MapEntry]) -> bool {
    entries.windows(2).all(|w| w[0].key < w[1].key)
}

/// Encode a single CBOR text-string key, returning its byte representation.
pub fn key(text: &str) -> Vec<u8> {
    let mut w = CborWriter::new();
    w.write_text(text);
    w.into_bytes()
}

/// Encode a single CBOR uint, returning its byte representation.
pub fn uint(n: u64) -> Vec<u8> {
    let mut w = CborWriter::new();
    w.write_u64(n);
    w.into_bytes()
}

/// Encode a single CBOR byte string, returning its byte representation.
pub fn bytes(b: &[u8]) -> Vec<u8> {
    let mut w = CborWriter::new();
    w.write_bytes(b);
    w.into_bytes()
}

/// Encode a single CBOR text string, returning its byte representation.
pub fn text(t: &str) -> Vec<u8> {
    let mut w = CborWriter::new();
    w.write_text(t);
    w.into_bytes()
}

/// Encode a CBOR null.
pub fn null() -> Vec<u8> {
    vec![SIMPLE_NULL]
}

/// Encode a CBOR bool.
pub fn boolean(b: bool) -> Vec<u8> {
    vec![if b { SIMPLE_TRUE } else { SIMPLE_FALSE }]
}

/// Verify that the bytes round-trip through ciborium::Value without changing.
///
/// This is the safety net: if our hand-rolled encoder emits something that
/// is not canonical (e.g. wrong length form), the round-trip will normalize
/// it and the comparison will fail. Used in `debug_assert!` and tests.
pub fn assert_canonical(bytes_in: &[u8]) -> Result<()> {
    let value: ciborium::Value =
        ciborium::de::from_reader(bytes_in).map_err(|e| Error::CborDecode(e.to_string()))?;
    let mut roundtrip = Vec::with_capacity(bytes_in.len());
    ciborium::ser::into_writer(&value, &mut roundtrip)
        .map_err(|e| Error::CborEncode(e.to_string()))?;
    if roundtrip == bytes_in {
        Ok(())
    } else {
        Err(Error::CborNotCanonical(
            "re-encode produced different bytes",
        ))
    }
}

/// Reader for the small set of CBOR shapes we need to consume.
///
/// We don't use ciborium's deserialize-into-Value path on the hot signature
/// path because that loses byte fidelity; we need to know the exact byte
/// range of the encoded `to-be-signed` portion of an envelope. This reader
/// gives us that.
pub struct CborReader<'a> {
    pub(crate) buf: &'a [u8],
    pub(crate) pos: usize,
}

impl<'a> CborReader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }

    pub fn at_end(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn read_byte(&mut self) -> Result<u8> {
        let b = *self
            .buf
            .get(self.pos)
            .ok_or_else(|| Error::CborDecode("unexpected EOF".into()))?;
        self.pos += 1;
        Ok(b)
    }

    fn read_n(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| Error::CborDecode("length overflow".into()))?;
        if end > self.buf.len() {
            return Err(Error::CborDecode("unexpected EOF".into()));
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    /// Read a CBOR head byte and return `(major_type, argument)`. Enforces
    /// shortest-form length encoding (deterministic encoding requirement).
    fn read_head(&mut self) -> Result<(u8, u64)> {
        let ib = self.read_byte()?;
        let major = ib >> 5;
        let info = ib & 0x1F;
        let arg = match info {
            0..=23 => info as u64,
            24 => {
                let b = self.read_byte()?;
                if b < 24 {
                    return Err(Error::CborNotCanonical(
                        "u8 length-form used for small value",
                    ));
                }
                b as u64
            }
            25 => {
                let bs = self.read_n(2)?;
                let v = u16::from_be_bytes([bs[0], bs[1]]) as u64;
                if v <= u8::MAX as u64 {
                    return Err(Error::CborNotCanonical(
                        "u16 length-form used for u8-fit value",
                    ));
                }
                v
            }
            26 => {
                let bs = self.read_n(4)?;
                let v = u32::from_be_bytes([bs[0], bs[1], bs[2], bs[3]]) as u64;
                if v <= u16::MAX as u64 {
                    return Err(Error::CborNotCanonical(
                        "u32 length-form used for u16-fit value",
                    ));
                }
                v
            }
            27 => {
                let bs = self.read_n(8)?;
                let v =
                    u64::from_be_bytes([bs[0], bs[1], bs[2], bs[3], bs[4], bs[5], bs[6], bs[7]]);
                if v <= u32::MAX as u64 {
                    return Err(Error::CborNotCanonical(
                        "u64 length-form used for u32-fit value",
                    ));
                }
                v
            }
            28..=30 => return Err(Error::CborDecode("reserved additional info".into())),
            31 => return Err(Error::CborNotCanonical("indefinite-length item")),
            _ => unreachable!(),
        };
        Ok((major, arg))
    }

    pub fn read_u64(&mut self) -> Result<u64> {
        let (major, arg) = self.read_head()?;
        if major != 0 {
            return Err(Error::CborDecode(format!(
                "expected uint, got major {major}"
            )));
        }
        Ok(arg)
    }

    pub fn read_bytes(&mut self) -> Result<&'a [u8]> {
        let (major, arg) = self.read_head()?;
        if major != 2 {
            return Err(Error::CborDecode(format!(
                "expected bytes, got major {major}"
            )));
        }
        self.read_n(arg as usize)
    }

    pub fn read_text(&mut self) -> Result<&'a str> {
        let (major, arg) = self.read_head()?;
        if major != 3 {
            return Err(Error::CborDecode(format!(
                "expected text, got major {major}"
            )));
        }
        let slice = self.read_n(arg as usize)?;
        core::str::from_utf8(slice)
            .map_err(|e| Error::CborDecode(format!("invalid utf-8 text: {e}")))
    }

    /// Read either a fixed-length byte string or a CBOR null. Returns `None`
    /// for null. Used for fields like the envelope's `to` (bstr / nil).
    pub fn read_bytes_or_null(&mut self) -> Result<Option<&'a [u8]>> {
        let peek = *self
            .buf
            .get(self.pos)
            .ok_or_else(|| Error::CborDecode("unexpected EOF".into()))?;
        if peek == SIMPLE_NULL {
            self.pos += 1;
            Ok(None)
        } else {
            self.read_bytes().map(Some)
        }
    }

    pub fn read_bool(&mut self) -> Result<bool> {
        let b = self.read_byte()?;
        match b {
            SIMPLE_FALSE => Ok(false),
            SIMPLE_TRUE => Ok(true),
            _ => Err(Error::CborDecode(format!("expected bool, got 0x{b:02X}"))),
        }
    }

    pub fn read_map_header(&mut self) -> Result<usize> {
        let (major, arg) = self.read_head()?;
        if major != 5 {
            return Err(Error::CborDecode(format!(
                "expected map, got major {major}"
            )));
        }
        if arg > MAX_CBOR_ENTRIES as u64 {
            return Err(Error::CborDecode(format!(
                "map count {arg} exceeds MAX_CBOR_ENTRIES"
            )));
        }
        Ok(arg as usize)
    }

    pub fn read_array_header(&mut self) -> Result<usize> {
        let (major, arg) = self.read_head()?;
        if major != 4 {
            return Err(Error::CborDecode(format!(
                "expected array, got major {major}"
            )));
        }
        if arg > MAX_CBOR_ENTRIES as u64 {
            return Err(Error::CborDecode(format!(
                "array count {arg} exceeds MAX_CBOR_ENTRIES"
            )));
        }
        Ok(arg as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shortest_form_uint_encoding() {
        // 0..=23 in head byte
        assert_eq!(uint(0), [0x00]);
        assert_eq!(uint(23), [0x17]);
        // 24..=255 with one-byte follow
        assert_eq!(uint(24), [0x18, 0x18]);
        assert_eq!(uint(255), [0x18, 0xFF]);
        // 256..=65535 with two-byte follow
        assert_eq!(uint(256), [0x19, 0x01, 0x00]);
        assert_eq!(uint(65535), [0x19, 0xFF, 0xFF]);
        // 65536..=u32::MAX with four-byte follow
        assert_eq!(uint(65536), [0x1A, 0x00, 0x01, 0x00, 0x00]);
    }

    #[test]
    fn text_encoding() {
        assert_eq!(text("v"), [0x61, b'v']);
        assert_eq!(text("from"), [0x64, b'f', b'r', b'o', b'm']);
    }

    #[test]
    fn bytes_encoding() {
        assert_eq!(bytes(&[]), [0x40]);
        assert_eq!(bytes(&[0xAA, 0xBB]), [0x42, 0xAA, 0xBB]);
    }

    #[test]
    fn reader_rejects_non_shortest_uint() {
        // 0x18 0x10 — using one-byte follow for a value of 16, which fits in head byte.
        let bad = [0x18u8, 0x10];
        let mut r = CborReader::new(&bad);
        let err = r.read_u64().unwrap_err();
        assert!(matches!(err, Error::CborNotCanonical(_)), "got {err:?}");
    }

    #[test]
    fn reader_round_trips_basic_types() {
        let mut w = CborWriter::new();
        w.write_u64(42);
        w.write_text("hello");
        w.write_bytes(&[1, 2, 3]);
        let bytes = w.into_bytes();

        let mut r = CborReader::new(&bytes);
        assert_eq!(r.read_u64().unwrap(), 42);
        assert_eq!(r.read_text().unwrap(), "hello");
        assert_eq!(r.read_bytes().unwrap(), &[1, 2, 3]);
        assert!(r.at_end());
    }

    #[test]
    fn map_entry_order_check_passes_when_sorted() {
        let entries = vec![
            MapEntry {
                key: key("a"),
                value: uint(1),
            },
            MapEntry {
                key: key("b"),
                value: uint(2),
            },
        ];
        let encoded = encode_map(&entries);
        assert_canonical(&encoded).unwrap();
    }

    #[test]
    fn map_header_rejects_count_above_max_entries() {
        // CBOR map header with count = u32::MAX (well above MAX_CBOR_ENTRIES).
        // Head byte 0xBA = major 5 (map) + info 26 (u32 follow).
        let mut bad = vec![0xBA];
        bad.extend_from_slice(&u32::MAX.to_be_bytes());
        let mut r = CborReader::new(&bad);
        let err = r.read_map_header().unwrap_err();
        assert!(
            matches!(err, Error::CborDecode(ref s) if s.contains("MAX_CBOR_ENTRIES")),
            "got {err:?}"
        );
    }

    #[test]
    fn array_header_rejects_count_above_max_entries() {
        // Head byte 0x9A = major 4 (array) + info 26 (u32 follow).
        let mut bad = vec![0x9A];
        bad.extend_from_slice(&u32::MAX.to_be_bytes());
        let mut r = CborReader::new(&bad);
        let err = r.read_array_header().unwrap_err();
        assert!(
            matches!(err, Error::CborDecode(ref s) if s.contains("MAX_CBOR_ENTRIES")),
            "got {err:?}"
        );
    }

    #[test]
    #[should_panic(expected = "canonical CBOR key order")]
    fn map_entry_order_check_panics_when_unsorted() {
        let entries = vec![
            MapEntry {
                key: key("b"),
                value: uint(2),
            },
            MapEntry {
                key: key("a"),
                value: uint(1),
            },
        ];
        let _ = encode_map(&entries);
    }
}
