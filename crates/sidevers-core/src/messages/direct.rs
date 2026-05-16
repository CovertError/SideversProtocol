//! Direct (unicast) message payloads — Appendix A range 0x20–0x2F (§3.9).
//!
//! Three message types are defined in v1:
//!
//!   * 0x20 DirectMessage — text, image, voice, or file. Month 2 covers
//!     `kind = "text"`; image/voice/file carry a `Reference` and land in
//!     month 3 with the storage layer.
//!   * 0x21 DirectReceipt — delivery and read receipts.
//!   * 0x22 DirectTyping  — ephemeral typing indicator.
//!
//! Canonical CBOR key order (RFC 8949 §4.2.1, bytewise on encoded keys):
//!
//!   DirectMessagePayload: body < kind < thread < reply_to
//!   DirectReceiptPayload: ref < status
//!   DirectTypingPayload : state

use crate::cbor::{self, CborReader, MapEntry};
use crate::error::{Error, Result};

/// Payload of a `DirectMessage` (0x20). For v1 month 2 only the `text` body
/// variant is fully wired; media bodies (image/voice/file) carry a `Reference`
/// and arrive with the storage layer in month 3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectMessagePayload {
    pub kind: DirectKind,
    pub body: DirectBody,
    pub reply_to: Option<[u8; 32]>,
    pub thread: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectKind {
    Text,
    Image,
    Voice,
    File,
    /// Forward-compatible escape hatch: unknown `kind` strings round-trip.
    Other(String),
}

impl DirectKind {
    pub fn as_str(&self) -> &str {
        match self {
            DirectKind::Text => "text",
            DirectKind::Image => "image",
            DirectKind::Voice => "voice",
            DirectKind::File => "file",
            DirectKind::Other(s) => s.as_str(),
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "text" => DirectKind::Text,
            "image" => DirectKind::Image,
            "voice" => DirectKind::Voice,
            "file" => DirectKind::File,
            other => DirectKind::Other(other.to_owned()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectBody {
    Text(String),
    /// Placeholder for `Reference` bodies. The CBOR bytes are passed through
    /// unparsed in month 2 so we can still round-trip a media DM; the
    /// `sidevers-storage` crate will parse these starting month 3.
    ReferenceBytes(Vec<u8>),
}

impl DirectMessagePayload {
    /// Encode in canonical CBOR. Key order: body, kind, thread, reply_to.
    pub fn encode(&self) -> Vec<u8> {
        let body_value = match &self.body {
            DirectBody::Text(s) => cbor::text(s),
            DirectBody::ReferenceBytes(b) => b.clone(),
        };
        let entries = [
            MapEntry {
                key: cbor::key("body"),
                value: body_value,
            },
            MapEntry {
                key: cbor::key("kind"),
                value: cbor::text(self.kind.as_str()),
            },
            MapEntry {
                key: cbor::key("thread"),
                value: match self.thread {
                    Some(h) => cbor::bytes(&h),
                    None => cbor::null(),
                },
            },
            MapEntry {
                key: cbor::key("reply_to"),
                value: match self.reply_to {
                    Some(h) => cbor::bytes(&h),
                    None => cbor::null(),
                },
            },
        ];
        cbor::encode_map(&entries)
    }

    /// Decode from canonical CBOR.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = CborReader::new(bytes);
        let n = r.read_map_header()?;
        if n != 4 {
            return Err(Error::CborDecode(format!(
                "DirectMessage expected 4 keys, got {n}"
            )));
        }

        // Expected canonical key order.
        let keys = ["body", "kind", "thread", "reply_to"];
        let mut body_text: Option<String> = None;
        let mut body_ref_bytes: Option<Vec<u8>> = None;
        let mut kind: Option<DirectKind> = None;
        let mut thread: Option<Option<[u8; 32]>> = None;
        let mut reply_to: Option<Option<[u8; 32]>> = None;

        for expected in keys {
            let k = r.read_text()?;
            if k != expected {
                return Err(Error::CborNotCanonical(
                    "DirectMessage keys not in canonical order",
                ));
            }
            match expected {
                "body" => {
                    // Peek: text or map (Reference)?
                    let next = *r
                        .remaining()
                        .first()
                        .ok_or_else(|| Error::CborDecode("missing body".into()))?;
                    let major = next >> 5;
                    if major == 3 {
                        body_text = Some(r.read_text()?.to_owned());
                    } else if major == 5 {
                        // Capture the canonical-encoded reference verbatim.
                        // The storage crate decodes it in month 3.
                        let start = r.position();
                        skip_value(&mut r)?;
                        let end = r.position();
                        body_ref_bytes = Some(bytes[start..end].to_vec());
                    } else {
                        return Err(Error::CborDecode(format!(
                            "DirectMessage body major type unexpected: {major}"
                        )));
                    }
                }
                "kind" => {
                    let s = r.read_text()?.to_owned();
                    kind = Some(DirectKind::parse(&s));
                }
                "thread" => {
                    thread = Some(read_optional_32(&mut r, "thread")?);
                }
                "reply_to" => {
                    reply_to = Some(read_optional_32(&mut r, "reply_to")?);
                }
                _ => unreachable!(),
            }
        }
        if !r.at_end() {
            return Err(Error::CborDecode(
                "trailing bytes after DirectMessage".into(),
            ));
        }
        let kind = kind.ok_or(Error::Invariant("missing kind"))?;
        let body = if let Some(t) = body_text {
            DirectBody::Text(t)
        } else if let Some(b) = body_ref_bytes {
            DirectBody::ReferenceBytes(b)
        } else {
            return Err(Error::Invariant("missing body"));
        };
        Ok(DirectMessagePayload {
            kind,
            body,
            reply_to: reply_to.ok_or(Error::Invariant("missing reply_to"))?,
            thread: thread.ok_or(Error::Invariant("missing thread"))?,
        })
    }
}

/// Payload of `DirectReceipt` (0x21).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectReceiptPayload {
    /// BLAKE3 hash of the envelope being acknowledged.
    pub message_ref: [u8; 32],
    pub status: ReceiptStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptStatus {
    Delivered,
    Read,
    Other(String),
}

impl ReceiptStatus {
    pub fn as_str(&self) -> &str {
        match self {
            ReceiptStatus::Delivered => "delivered",
            ReceiptStatus::Read => "read",
            ReceiptStatus::Other(s) => s.as_str(),
        }
    }
    pub fn parse(s: &str) -> Self {
        match s {
            "delivered" => ReceiptStatus::Delivered,
            "read" => ReceiptStatus::Read,
            other => ReceiptStatus::Other(other.to_owned()),
        }
    }
}

impl DirectReceiptPayload {
    pub fn encode(&self) -> Vec<u8> {
        let entries = [
            MapEntry {
                key: cbor::key("ref"),
                value: cbor::bytes(&self.message_ref),
            },
            MapEntry {
                key: cbor::key("status"),
                value: cbor::text(self.status.as_str()),
            },
        ];
        cbor::encode_map(&entries)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = CborReader::new(bytes);
        let n = r.read_map_header()?;
        if n != 2 {
            return Err(Error::CborDecode(format!(
                "DirectReceipt expected 2 keys, got {n}"
            )));
        }
        if r.read_text()? != "ref" {
            return Err(Error::CborNotCanonical("DirectReceipt expects 'ref' first"));
        }
        let rbytes = r.read_bytes()?;
        if rbytes.len() != 32 {
            return Err(Error::BadFieldLength {
                field: "ref",
                expected: 32,
                got: rbytes.len(),
            });
        }
        let mut message_ref = [0u8; 32];
        message_ref.copy_from_slice(rbytes);
        if r.read_text()? != "status" {
            return Err(Error::CborNotCanonical(
                "DirectReceipt expects 'status' second",
            ));
        }
        let status = ReceiptStatus::parse(r.read_text()?);
        if !r.at_end() {
            return Err(Error::CborDecode(
                "trailing bytes after DirectReceipt".into(),
            ));
        }
        Ok(Self {
            message_ref,
            status,
        })
    }
}

/// Payload of `DirectTyping` (0x22).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectTypingPayload {
    pub state: TypingState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypingState {
    Started,
    Stopped,
    Other(String),
}

impl TypingState {
    pub fn as_str(&self) -> &str {
        match self {
            TypingState::Started => "started",
            TypingState::Stopped => "stopped",
            TypingState::Other(s) => s.as_str(),
        }
    }
    pub fn parse(s: &str) -> Self {
        match s {
            "started" => TypingState::Started,
            "stopped" => TypingState::Stopped,
            other => TypingState::Other(other.to_owned()),
        }
    }
}

impl DirectTypingPayload {
    pub fn encode(&self) -> Vec<u8> {
        let entries = [MapEntry {
            key: cbor::key("state"),
            value: cbor::text(self.state.as_str()),
        }];
        cbor::encode_map(&entries)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = CborReader::new(bytes);
        let n = r.read_map_header()?;
        if n != 1 {
            return Err(Error::CborDecode(format!(
                "DirectTyping expected 1 key, got {n}"
            )));
        }
        if r.read_text()? != "state" {
            return Err(Error::CborNotCanonical("DirectTyping expects 'state'"));
        }
        let state = TypingState::parse(r.read_text()?);
        if !r.at_end() {
            return Err(Error::CborDecode(
                "trailing bytes after DirectTyping".into(),
            ));
        }
        Ok(Self { state })
    }
}

fn read_optional_32(r: &mut CborReader<'_>, field: &'static str) -> Result<Option<[u8; 32]>> {
    match r.read_bytes_or_null()? {
        None => Ok(None),
        Some(b) => {
            if b.len() != 32 {
                return Err(Error::BadFieldLength {
                    field,
                    expected: 32,
                    got: b.len(),
                });
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(b);
            Ok(Some(arr))
        }
    }
}

/// Advance the reader past one CBOR value (skipping its bytes).
/// Supports the major types we use; sufficient for capturing a `Reference`.
fn skip_value(r: &mut CborReader<'_>) -> Result<()> {
    skip_value_inner(r, crate::cbor::MAX_CBOR_SKIP_DEPTH)
}

fn skip_value_inner(r: &mut CborReader<'_>, depth: u8) -> Result<()> {
    if depth == 0 {
        return Err(Error::CborDecode(
            "skip_value depth budget exhausted (deeply nested CBOR)".into(),
        ));
    }
    let start = r.position();
    let first = *r
        .remaining()
        .first()
        .ok_or_else(|| Error::CborDecode("EOF in skip".into()))?;
    let major = first >> 5;
    match major {
        0 | 1 => {
            r.read_u64()?;
        }
        2 => {
            r.read_bytes()?;
        }
        3 => {
            r.read_text()?;
        }
        4 => {
            let n = r.read_array_header()?;
            for _ in 0..n {
                skip_value_inner(r, depth - 1)?;
            }
        }
        5 => {
            let n = r.read_map_header()?;
            for _ in 0..n {
                skip_value_inner(r, depth - 1)?;
                skip_value_inner(r, depth - 1)?;
            }
        }
        7 => {
            // Simple values (null/true/false). Single byte for the ones we use.
            r.read_bytes_or_null()?;
        }
        _ => return Err(Error::CborDecode(format!("unexpected major {major}"))),
    }
    debug_assert!(r.position() > start);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::CborWriter;

    /// Build a CBOR map nested `depth` levels deep, terminated with a `null`.
    fn nested_map(depth: usize) -> Vec<u8> {
        let mut out = Vec::new();
        for _ in 0..depth {
            // Each level: 1-entry map with a 1-byte key.
            out.push(0xA1); // map(1)
            let mut k = CborWriter::new();
            k.write_text("a");
            out.extend_from_slice(&k.into_bytes());
        }
        // Innermost value: null.
        out.push(0xF6);
        out
    }

    #[test]
    fn skip_value_rejects_deeply_nested_cbor() {
        // Just above the budget — must error before stack overflow.
        let depth_attack = crate::cbor::MAX_CBOR_SKIP_DEPTH as usize + 1;
        let bytes = nested_map(depth_attack);
        let mut r = CborReader::new(&bytes);
        let err = skip_value(&mut r).unwrap_err();
        assert!(
            matches!(err, Error::CborDecode(ref s) if s.contains("depth budget")),
            "got {err:?}"
        );
    }

    #[test]
    fn skip_value_accepts_shallow_nesting() {
        // 3 levels of nesting — well within the budget.
        let bytes = nested_map(3);
        let mut r = CborReader::new(&bytes);
        skip_value(&mut r).expect("3-level skip should succeed");
    }

    #[test]
    fn direct_message_text_roundtrip() {
        let m = DirectMessagePayload {
            kind: DirectKind::Text,
            body: DirectBody::Text("hi there".to_owned()),
            reply_to: None,
            thread: None,
        };
        let bytes = m.encode();
        let decoded = DirectMessagePayload::decode(&bytes).unwrap();
        assert_eq!(decoded, m);
    }

    #[test]
    fn direct_message_with_thread_and_reply() {
        let m = DirectMessagePayload {
            kind: DirectKind::Text,
            body: DirectBody::Text("ack".to_owned()),
            reply_to: Some([7u8; 32]),
            thread: Some([8u8; 32]),
        };
        let bytes = m.encode();
        let decoded = DirectMessagePayload::decode(&bytes).unwrap();
        assert_eq!(decoded, m);
    }

    #[test]
    fn direct_message_unknown_kind_round_trips() {
        let m = DirectMessagePayload {
            kind: DirectKind::Other("sticker".to_owned()),
            body: DirectBody::Text("🥹".to_owned()),
            reply_to: None,
            thread: None,
        };
        let bytes = m.encode();
        let decoded = DirectMessagePayload::decode(&bytes).unwrap();
        assert_eq!(decoded, m);
    }

    #[test]
    fn direct_receipt_roundtrip() {
        let r = DirectReceiptPayload {
            message_ref: [1u8; 32],
            status: ReceiptStatus::Read,
        };
        let bytes = r.encode();
        let decoded = DirectReceiptPayload::decode(&bytes).unwrap();
        assert_eq!(decoded, r);
    }

    #[test]
    fn direct_typing_roundtrip() {
        let t = DirectTypingPayload {
            state: TypingState::Started,
        };
        let bytes = t.encode();
        let decoded = DirectTypingPayload::decode(&bytes).unwrap();
        assert_eq!(decoded, t);
    }
}
