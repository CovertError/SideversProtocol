//! Public-layer payloads (protocol spec §9, Phase 2 wire scaffold).
//!
//! The Public layer is the part of Sidevers a sidevers.com Laravel
//! registry resolves over: handle lookup (`@user` → side address),
//! signed claims of a handle, page publish/fetch (a side's
//! addressable personal pages), broadcast announcements gossiped on
//! the wire, and directory entries the registry curates.
//!
//! This module ships the **wire codecs only**. There are no
//! `serve_public` handlers in `node.rs` because the Phase 2 spec is
//! deliberately Laravel-side; the Rust node needs to be able to
//! parse, sign, and dispatch these envelopes (e.g. to publish a page
//! to a registry that's listening), but the registry's response
//! semantics are out of scope for the reference implementation.
//!
//! ## Wire-format convention (mirrors §3.1)
//!
//! Each payload is a CBOR map in canonical key order (RFC 8949
//! §4.2.1 — keys sorted by encoded-length then bytewise). Signed
//! payloads carry an inline 64-byte Ed25519 signature over the
//! BLAKE3 hash of the "unsigned" form (the same map minus the
//! `signature` field). `from_wire_bytes` verifies the signature
//! and the round-trip-to-canonical check before returning.
//!
//! ## Message types
//!
//! | Type | Const | Signed? | Notes |
//! |------|-------|---------|-------|
//! | `HandleResolve`  | `0x60` | no | request: "look up @handle" |
//! | `HandleAttest`   | `0x61` | yes | side claims a handle |
//! | `PagePublish`    | `0x62` | yes | side publishes a page |
//! | `PageFetch`      | `0x63` | no | request: "give me <side>/<slug>" |
//! | `PageDeliver`    | `0x64` | wraps a signed PagePublish |
//! | `Announcement`   | `0x65` | yes | gossiped broadcast |
//! | `DirectoryEntry` | `0x66` | no (composite) | curated by the registry |

use crate::cbor::{self, CborReader, CborWriter, MapEntry};
use crate::error::{Error, Result};
use crate::keys::{PUBLIC_KEY_LEN, PublicKey, SIGNATURE_LEN, SideKey};

// ============================================================================
// HandleResolvePayload (0x60) — unsigned request
// ============================================================================
//
// Federated form (spec §9.3, Phase 2 — federated namespace decision): a
// handle is the pair `(handle_local, domain)`, not a single opaque
// string. The display form is `omar@sidevers.com`; on the wire we
// carry the two halves separately so a responder can reject anything
// that isn't its own domain — no registry speaks for handles outside
// its own namespace.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandleResolvePayload {
    /// Local part — the bit before the `@`. Lowercase, identifier-shaped.
    pub handle_local: String,
    /// Domain the responder is being asked to resolve under. The
    /// responder MUST refuse if this doesn't match its served domain.
    pub domain: String,
}

impl HandleResolvePayload {
    /// Convenience for the display form `<local>@<domain>`.
    pub fn display(&self) -> String {
        format!("{}@{}", self.handle_local, self.domain)
    }

    pub fn encode(&self) -> Vec<u8> {
        // Canonical: handle_local(12) > domain(6). Length order:
        // domain(6) < handle_local(12). Two entries.
        let entries = [
            MapEntry {
                key: cbor::key("domain"),
                value: cbor::text(&self.domain),
            },
            MapEntry {
                key: cbor::key("handle_local"),
                value: cbor::text(&self.handle_local),
            },
        ];
        cbor::encode_map(&entries)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = CborReader::new(bytes);
        let n = r.read_map_header()?;
        if n != 2 {
            return Err(Error::CborDecode(format!(
                "HandleResolve expected 2 keys, got {n}"
            )));
        }
        if r.read_text()? != "domain" {
            return Err(Error::CborNotCanonical(
                "HandleResolve: expected 'domain' first",
            ));
        }
        let domain = r.read_text()?.to_owned();
        if r.read_text()? != "handle_local" {
            return Err(Error::CborNotCanonical(
                "HandleResolve: expected 'handle_local' second",
            ));
        }
        let handle_local = r.read_text()?.to_owned();
        if !r.at_end() {
            return Err(Error::CborDecode(
                "trailing bytes after HandleResolve".into(),
            ));
        }
        Ok(Self {
            handle_local,
            domain,
        })
    }
}

// ============================================================================
// HandleAttestPayload (0x61) — signed claim
// ============================================================================
//
// "I am side X, I claim handle_local under domain D, issued at T."
//
// **The domain is in the signed digest.** A signature over just
// (side, handle, issued_at) would be replayable across registries:
// an attacker could lift Alice's attestation for `alice@example.com`
// and present it under `sidevers.com` as proof of `alice@sidevers.com`.
// Including `domain` in the signed bytes binds the claim to one
// namespace. This is the DKIM `d=` selector pattern.
//
// Display form: `<handle_local>@<domain>`. Wire form: two strings.
// `display()` is the convenience helper.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandleAttestPayload {
    pub side: [u8; PUBLIC_KEY_LEN],
    pub handle_local: String,
    pub domain: String,
    pub issued_at: u64,
    pub signature: [u8; SIGNATURE_LEN],
}

impl HandleAttestPayload {
    /// `<handle_local>@<domain>` — what humans see, never what's signed.
    pub fn display(&self) -> String {
        format!("{}@{}", self.handle_local, self.domain)
    }

    fn encode_unsigned(
        side: &[u8; PUBLIC_KEY_LEN],
        handle_local: &str,
        domain: &str,
        issued_at: u64,
    ) -> Vec<u8> {
        // Canonical key order (raw text length, ties → bytewise on
        // encoded bytes): side(4) < domain(6) < handle_local(12) <
        // issued_at(9 = same length as no other length-9 here besides
        // signature, but signature is in to_wire_bytes only).
        // Tie at 6: domain ("d") < handle_local ("h") wait — handle_local
        // is length 12, not 6. So no tie. Order: side, domain,
        // handle_local, issued_at.
        let entries = [
            MapEntry {
                key: cbor::key("side"),
                value: cbor::bytes(side),
            },
            MapEntry {
                key: cbor::key("domain"),
                value: cbor::text(domain),
            },
            MapEntry {
                key: cbor::key("issued_at"),
                value: cbor::uint(issued_at),
            },
            MapEntry {
                key: cbor::key("handle_local"),
                value: cbor::text(handle_local),
            },
        ];
        cbor::encode_map(&entries)
    }

    pub fn sign(
        side_key: &SideKey,
        handle_local: impl Into<String>,
        domain: impl Into<String>,
        issued_at: u64,
    ) -> Result<Self> {
        let pk = side_key.public_bytes();
        let handle_local = handle_local.into();
        let domain = domain.into();
        let unsigned = Self::encode_unsigned(&pk, &handle_local, &domain, issued_at);
        let digest = blake3::hash(&unsigned);
        let signature = side_key.sign(digest.as_bytes());
        Ok(Self {
            side: pk,
            handle_local,
            domain,
            issued_at,
            signature,
        })
    }

    pub fn to_wire_bytes(&self) -> Vec<u8> {
        // Canonical with signature appended. Lengths: side(4),
        // domain(6), issued_at(9), signature(9), handle_local(12).
        // 9-tie: issued_at < signature bytewise ('i' < 's').
        let entries = [
            MapEntry {
                key: cbor::key("side"),
                value: cbor::bytes(&self.side),
            },
            MapEntry {
                key: cbor::key("domain"),
                value: cbor::text(&self.domain),
            },
            MapEntry {
                key: cbor::key("issued_at"),
                value: cbor::uint(self.issued_at),
            },
            MapEntry {
                key: cbor::key("signature"),
                value: cbor::bytes(&self.signature),
            },
            MapEntry {
                key: cbor::key("handle_local"),
                value: cbor::text(&self.handle_local),
            },
        ];
        cbor::encode_map(&entries)
    }

    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = CborReader::new(bytes);
        let n = r.read_map_header()?;
        if n != 5 {
            return Err(Error::CborDecode(format!(
                "HandleAttest expected 5 keys, got {n}"
            )));
        }
        let expected = ["side", "domain", "issued_at", "signature", "handle_local"];
        let mut side: Option<[u8; PUBLIC_KEY_LEN]> = None;
        let mut domain: Option<String> = None;
        let mut handle_local: Option<String> = None;
        let mut issued_at: Option<u64> = None;
        let mut signature: Option<[u8; SIGNATURE_LEN]> = None;
        for e in expected {
            let k = r.read_text()?;
            if k != e {
                return Err(Error::CborNotCanonical(
                    "HandleAttest keys not in canonical order",
                ));
            }
            match e {
                "side" => {
                    let b = r.read_bytes()?;
                    if b.len() != PUBLIC_KEY_LEN {
                        return Err(Error::BadFieldLength {
                            field: "side",
                            expected: PUBLIC_KEY_LEN,
                            got: b.len(),
                        });
                    }
                    let mut arr = [0u8; PUBLIC_KEY_LEN];
                    arr.copy_from_slice(b);
                    side = Some(arr);
                }
                "domain" => domain = Some(r.read_text()?.to_owned()),
                "handle_local" => handle_local = Some(r.read_text()?.to_owned()),
                "issued_at" => issued_at = Some(r.read_u64()?),
                "signature" => {
                    let b = r.read_bytes()?;
                    if b.len() != SIGNATURE_LEN {
                        return Err(Error::BadFieldLength {
                            field: "signature",
                            expected: SIGNATURE_LEN,
                            got: b.len(),
                        });
                    }
                    let mut arr = [0u8; SIGNATURE_LEN];
                    arr.copy_from_slice(b);
                    signature = Some(arr);
                }
                _ => unreachable!(),
            }
        }
        if !r.at_end() {
            return Err(Error::CborDecode(
                "trailing bytes after HandleAttest".into(),
            ));
        }
        let side = side.ok_or(Error::Invariant("missing side"))?;
        let domain = domain.ok_or(Error::Invariant("missing domain"))?;
        let handle_local = handle_local.ok_or(Error::Invariant("missing handle_local"))?;
        let issued_at = issued_at.ok_or(Error::Invariant("missing issued_at"))?;
        let signature = signature.ok_or(Error::Invariant("missing signature"))?;

        let unsigned = Self::encode_unsigned(&side, &handle_local, &domain, issued_at);
        let digest = blake3::hash(&unsigned);
        PublicKey::from_bytes(&side)?.verify(digest.as_bytes(), &signature)?;

        let payload = Self {
            side,
            handle_local,
            domain,
            issued_at,
            signature,
        };
        if payload.to_wire_bytes() != bytes {
            return Err(Error::CborNotCanonical(
                "HandleAttest bytes are not canonical re-encode",
            ));
        }
        Ok(payload)
    }
}

// ============================================================================
// PagePublishPayload (0x62) — signed page from a side
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PagePublishPayload {
    pub side: [u8; PUBLIC_KEY_LEN],
    pub slug: String,
    pub mime: String,
    pub content: Vec<u8>,
    pub published_at: u64,
    pub signature: [u8; SIGNATURE_LEN],
}

impl PagePublishPayload {
    fn encode_unsigned(
        side: &[u8; PUBLIC_KEY_LEN],
        mime: &str,
        slug: &str,
        content: &[u8],
        published_at: u64,
    ) -> Vec<u8> {
        // Canonical: mime(4), side(4), slug(4) — bytewise: m < s, then side<slug.
        // → mime, side, slug, content(7), published_at(12)
        let entries = [
            MapEntry {
                key: cbor::key("mime"),
                value: cbor::text(mime),
            },
            MapEntry {
                key: cbor::key("side"),
                value: cbor::bytes(side),
            },
            MapEntry {
                key: cbor::key("slug"),
                value: cbor::text(slug),
            },
            MapEntry {
                key: cbor::key("content"),
                value: cbor::bytes(content),
            },
            MapEntry {
                key: cbor::key("published_at"),
                value: cbor::uint(published_at),
            },
        ];
        cbor::encode_map(&entries)
    }

    pub fn sign(
        side_key: &SideKey,
        slug: impl Into<String>,
        mime: impl Into<String>,
        content: Vec<u8>,
        published_at: u64,
    ) -> Result<Self> {
        let pk = side_key.public_bytes();
        let slug = slug.into();
        let mime = mime.into();
        let unsigned = Self::encode_unsigned(&pk, &mime, &slug, &content, published_at);
        let digest = blake3::hash(&unsigned);
        let signature = side_key.sign(digest.as_bytes());
        Ok(Self {
            side: pk,
            slug,
            mime,
            content,
            published_at,
            signature,
        })
    }

    pub fn to_wire_bytes(&self) -> Vec<u8> {
        // Canonical with signature: mime, side, slug, content(7),
        // signature(9), published_at(12).
        let entries = [
            MapEntry {
                key: cbor::key("mime"),
                value: cbor::text(&self.mime),
            },
            MapEntry {
                key: cbor::key("side"),
                value: cbor::bytes(&self.side),
            },
            MapEntry {
                key: cbor::key("slug"),
                value: cbor::text(&self.slug),
            },
            MapEntry {
                key: cbor::key("content"),
                value: cbor::bytes(&self.content),
            },
            MapEntry {
                key: cbor::key("signature"),
                value: cbor::bytes(&self.signature),
            },
            MapEntry {
                key: cbor::key("published_at"),
                value: cbor::uint(self.published_at),
            },
        ];
        cbor::encode_map(&entries)
    }

    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = CborReader::new(bytes);
        let n = r.read_map_header()?;
        if n != 6 {
            return Err(Error::CborDecode(format!(
                "PagePublish expected 6 keys, got {n}"
            )));
        }
        let expected = [
            "mime",
            "side",
            "slug",
            "content",
            "signature",
            "published_at",
        ];
        let mut mime: Option<String> = None;
        let mut side: Option<[u8; PUBLIC_KEY_LEN]> = None;
        let mut slug: Option<String> = None;
        let mut content: Option<Vec<u8>> = None;
        let mut signature: Option<[u8; SIGNATURE_LEN]> = None;
        let mut published_at: Option<u64> = None;
        for e in expected {
            let k = r.read_text()?;
            if k != e {
                return Err(Error::CborNotCanonical(
                    "PagePublish keys not in canonical order",
                ));
            }
            match e {
                "mime" => mime = Some(r.read_text()?.to_owned()),
                "side" => {
                    let b = r.read_bytes()?;
                    if b.len() != PUBLIC_KEY_LEN {
                        return Err(Error::BadFieldLength {
                            field: "side",
                            expected: PUBLIC_KEY_LEN,
                            got: b.len(),
                        });
                    }
                    let mut arr = [0u8; PUBLIC_KEY_LEN];
                    arr.copy_from_slice(b);
                    side = Some(arr);
                }
                "slug" => slug = Some(r.read_text()?.to_owned()),
                "content" => content = Some(r.read_bytes()?.to_vec()),
                "signature" => {
                    let b = r.read_bytes()?;
                    if b.len() != SIGNATURE_LEN {
                        return Err(Error::BadFieldLength {
                            field: "signature",
                            expected: SIGNATURE_LEN,
                            got: b.len(),
                        });
                    }
                    let mut arr = [0u8; SIGNATURE_LEN];
                    arr.copy_from_slice(b);
                    signature = Some(arr);
                }
                "published_at" => published_at = Some(r.read_u64()?),
                _ => unreachable!(),
            }
        }
        if !r.at_end() {
            return Err(Error::CborDecode("trailing bytes after PagePublish".into()));
        }
        let mime = mime.ok_or(Error::Invariant("missing mime"))?;
        let side = side.ok_or(Error::Invariant("missing side"))?;
        let slug = slug.ok_or(Error::Invariant("missing slug"))?;
        let content = content.ok_or(Error::Invariant("missing content"))?;
        let signature = signature.ok_or(Error::Invariant("missing signature"))?;
        let published_at = published_at.ok_or(Error::Invariant("missing published_at"))?;

        let unsigned = Self::encode_unsigned(&side, &mime, &slug, &content, published_at);
        let digest = blake3::hash(&unsigned);
        PublicKey::from_bytes(&side)?.verify(digest.as_bytes(), &signature)?;

        let payload = Self {
            side,
            slug,
            mime,
            content,
            published_at,
            signature,
        };
        if payload.to_wire_bytes() != bytes {
            return Err(Error::CborNotCanonical(
                "PagePublish bytes are not canonical re-encode",
            ));
        }
        Ok(payload)
    }
}

// ============================================================================
// PageFetchPayload (0x63) — unsigned request "give me <side>/<slug>"
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageFetchPayload {
    pub side: [u8; PUBLIC_KEY_LEN],
    pub slug: String,
}

impl PageFetchPayload {
    pub fn encode(&self) -> Vec<u8> {
        // Canonical: side(4) < slug(4) — bytewise side < slug ('i' < 'l').
        let entries = [
            MapEntry {
                key: cbor::key("side"),
                value: cbor::bytes(&self.side),
            },
            MapEntry {
                key: cbor::key("slug"),
                value: cbor::text(&self.slug),
            },
        ];
        cbor::encode_map(&entries)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = CborReader::new(bytes);
        let n = r.read_map_header()?;
        if n != 2 {
            return Err(Error::CborDecode(format!(
                "PageFetch expected 2 keys, got {n}"
            )));
        }
        if r.read_text()? != "side" {
            return Err(Error::CborNotCanonical("PageFetch expects 'side' first"));
        }
        let b = r.read_bytes()?;
        if b.len() != PUBLIC_KEY_LEN {
            return Err(Error::BadFieldLength {
                field: "side",
                expected: PUBLIC_KEY_LEN,
                got: b.len(),
            });
        }
        let mut side = [0u8; PUBLIC_KEY_LEN];
        side.copy_from_slice(b);
        if r.read_text()? != "slug" {
            return Err(Error::CborNotCanonical("PageFetch expects 'slug' second"));
        }
        let slug = r.read_text()?.to_owned();
        if !r.at_end() {
            return Err(Error::CborDecode("trailing bytes after PageFetch".into()));
        }
        Ok(Self { side, slug })
    }
}

// ============================================================================
// PageDeliverPayload (0x64) — wraps a signed PagePublish as response.
//
// The inner page is carried as an opaque CBOR byte string (the
// PagePublish's to_wire_bytes). This keeps the outer envelope's
// CBOR shape trivial (one bstr field) and avoids needing a generic
// skip-CBOR-value helper to find the inner map's byte span.
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageDeliverPayload {
    pub page: PagePublishPayload,
}

impl PageDeliverPayload {
    pub fn encode(&self) -> Vec<u8> {
        let entries = [MapEntry {
            key: cbor::key("page"),
            value: cbor::bytes(&self.page.to_wire_bytes()),
        }];
        cbor::encode_map(&entries)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = CborReader::new(bytes);
        let n = r.read_map_header()?;
        if n != 1 {
            return Err(Error::CborDecode(format!(
                "PageDeliver expected 1 key, got {n}"
            )));
        }
        if r.read_text()? != "page" {
            return Err(Error::CborNotCanonical("PageDeliver expects 'page'"));
        }
        let page_bytes = r.read_bytes()?;
        let page = PagePublishPayload::from_wire_bytes(page_bytes)?;
        if !r.at_end() {
            return Err(Error::CborDecode("trailing bytes after PageDeliver".into()));
        }
        Ok(Self { page })
    }
}

// ============================================================================
// AnnouncementPayload (0x65) — signed broadcast for gossip-fanout discovery
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnouncementPayload {
    pub side: [u8; PUBLIC_KEY_LEN],
    pub body: String,
    pub created_at: u64,
    pub signature: [u8; SIGNATURE_LEN],
}

impl AnnouncementPayload {
    fn encode_unsigned(side: &[u8; PUBLIC_KEY_LEN], body: &str, created_at: u64) -> Vec<u8> {
        // Canonical: body(4) < side(4) — bytewise 'b' < 's'; then created_at(10).
        let entries = [
            MapEntry {
                key: cbor::key("body"),
                value: cbor::text(body),
            },
            MapEntry {
                key: cbor::key("side"),
                value: cbor::bytes(side),
            },
            MapEntry {
                key: cbor::key("created_at"),
                value: cbor::uint(created_at),
            },
        ];
        cbor::encode_map(&entries)
    }

    pub fn sign(side_key: &SideKey, body: impl Into<String>, created_at: u64) -> Result<Self> {
        let pk = side_key.public_bytes();
        let body = body.into();
        let unsigned = Self::encode_unsigned(&pk, &body, created_at);
        let digest = blake3::hash(&unsigned);
        let signature = side_key.sign(digest.as_bytes());
        Ok(Self {
            side: pk,
            body,
            created_at,
            signature,
        })
    }

    pub fn to_wire_bytes(&self) -> Vec<u8> {
        // Canonical with signature: body(4), side(4), signature(9), created_at(10).
        let entries = [
            MapEntry {
                key: cbor::key("body"),
                value: cbor::text(&self.body),
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
                key: cbor::key("created_at"),
                value: cbor::uint(self.created_at),
            },
        ];
        cbor::encode_map(&entries)
    }

    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = CborReader::new(bytes);
        let n = r.read_map_header()?;
        if n != 4 {
            return Err(Error::CborDecode(format!(
                "Announcement expected 4 keys, got {n}"
            )));
        }
        let expected = ["body", "side", "signature", "created_at"];
        let mut body: Option<String> = None;
        let mut side: Option<[u8; PUBLIC_KEY_LEN]> = None;
        let mut signature: Option<[u8; SIGNATURE_LEN]> = None;
        let mut created_at: Option<u64> = None;
        for e in expected {
            let k = r.read_text()?;
            if k != e {
                return Err(Error::CborNotCanonical(
                    "Announcement keys not in canonical order",
                ));
            }
            match e {
                "body" => body = Some(r.read_text()?.to_owned()),
                "side" => {
                    let b = r.read_bytes()?;
                    if b.len() != PUBLIC_KEY_LEN {
                        return Err(Error::BadFieldLength {
                            field: "side",
                            expected: PUBLIC_KEY_LEN,
                            got: b.len(),
                        });
                    }
                    let mut arr = [0u8; PUBLIC_KEY_LEN];
                    arr.copy_from_slice(b);
                    side = Some(arr);
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
                    let mut arr = [0u8; SIGNATURE_LEN];
                    arr.copy_from_slice(b);
                    signature = Some(arr);
                }
                "created_at" => created_at = Some(r.read_u64()?),
                _ => unreachable!(),
            }
        }
        if !r.at_end() {
            return Err(Error::CborDecode(
                "trailing bytes after Announcement".into(),
            ));
        }
        let body = body.ok_or(Error::Invariant("missing body"))?;
        let side = side.ok_or(Error::Invariant("missing side"))?;
        let signature = signature.ok_or(Error::Invariant("missing signature"))?;
        let created_at = created_at.ok_or(Error::Invariant("missing created_at"))?;

        let unsigned = Self::encode_unsigned(&side, &body, created_at);
        let digest = blake3::hash(&unsigned);
        PublicKey::from_bytes(&side)?.verify(digest.as_bytes(), &signature)?;

        let payload = Self {
            side,
            body,
            created_at,
            signature,
        };
        if payload.to_wire_bytes() != bytes {
            return Err(Error::CborNotCanonical(
                "Announcement bytes are not canonical re-encode",
            ));
        }
        Ok(payload)
    }
}

// ============================================================================
// DirectoryEntryPayload (0x66) — registry-curated entry, composite of attestations
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryEntryPayload {
    pub side: [u8; PUBLIC_KEY_LEN],
    pub handle: String,
    pub attestations: Vec<HandleAttestPayload>,
}

impl DirectoryEntryPayload {
    pub fn encode(&self) -> Vec<u8> {
        // Canonical: side(4) < handle(6) < attestations(12).
        // Each attestation is wrapped as an opaque bstr (containing
        // the to_wire_bytes of the HandleAttest) so the array element
        // type is uniform and trivial to parse.
        let mut attest_w = CborWriter::new();
        attest_w.write_array_header(self.attestations.len());
        for a in &self.attestations {
            attest_w.write_bytes(&a.to_wire_bytes());
        }
        let entries = [
            MapEntry {
                key: cbor::key("side"),
                value: cbor::bytes(&self.side),
            },
            MapEntry {
                key: cbor::key("handle"),
                value: cbor::text(&self.handle),
            },
            MapEntry {
                key: cbor::key("attestations"),
                value: attest_w.into_bytes(),
            },
        ];
        cbor::encode_map(&entries)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = CborReader::new(bytes);
        let n = r.read_map_header()?;
        if n != 3 {
            return Err(Error::CborDecode(format!(
                "DirectoryEntry expected 3 keys, got {n}"
            )));
        }
        if r.read_text()? != "side" {
            return Err(Error::CborNotCanonical(
                "DirectoryEntry expects 'side' first",
            ));
        }
        let b = r.read_bytes()?;
        if b.len() != PUBLIC_KEY_LEN {
            return Err(Error::BadFieldLength {
                field: "side",
                expected: PUBLIC_KEY_LEN,
                got: b.len(),
            });
        }
        let mut side = [0u8; PUBLIC_KEY_LEN];
        side.copy_from_slice(b);
        if r.read_text()? != "handle" {
            return Err(Error::CborNotCanonical(
                "DirectoryEntry expects 'handle' second",
            ));
        }
        let handle = r.read_text()?.to_owned();
        if r.read_text()? != "attestations" {
            return Err(Error::CborNotCanonical(
                "DirectoryEntry expects 'attestations' third",
            ));
        }
        let count = r.read_array_header()?;
        let mut attestations = Vec::with_capacity(count);
        for _ in 0..count {
            let att_bytes = r.read_bytes()?;
            attestations.push(HandleAttestPayload::from_wire_bytes(att_bytes)?);
        }
        if !r.at_end() {
            return Err(Error::CborDecode(
                "trailing bytes after DirectoryEntry".into(),
            ));
        }
        Ok(Self {
            side,
            handle,
            attestations,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::MasterKey;

    fn fixture_side(seed: u8) -> SideKey {
        let m = MasterKey::from_seed(&[seed; 32]);
        m.derive_side(&"public".into()).unwrap()
    }

    #[test]
    fn handle_resolve_round_trip() {
        let p = HandleResolvePayload {
            handle_local: "omar".to_owned(),
            domain: "sidevers.com".to_owned(),
        };
        let bytes = p.encode();
        let decoded = HandleResolvePayload::decode(&bytes).unwrap();
        assert_eq!(decoded, p);
        assert_eq!(decoded.display(), "omar@sidevers.com");
    }

    #[test]
    fn handle_attest_signed_round_trip() {
        let side = fixture_side(0x11);
        let p = HandleAttestPayload::sign(&side, "omar", "sidevers.com", 1_700_000_000).unwrap();
        let bytes = p.to_wire_bytes();
        let decoded = HandleAttestPayload::from_wire_bytes(&bytes).unwrap();
        assert_eq!(decoded, p);
        assert_eq!(decoded.side, side.public_bytes());
        assert_eq!(decoded.display(), "omar@sidevers.com");
    }

    #[test]
    fn handle_attest_tamper_breaks_signature() {
        let side = fixture_side(0x22);
        let mut p = HandleAttestPayload::sign(&side, "x", "sidevers.com", 1).unwrap();
        p.handle_local = "y".to_owned();
        let bytes = p.to_wire_bytes();
        let err = HandleAttestPayload::from_wire_bytes(&bytes).unwrap_err();
        assert!(matches!(err, Error::SignatureInvalid));
    }

    #[test]
    fn handle_attest_cross_domain_replay_breaks_signature() {
        // The whole point of putting `domain` in the signed payload:
        // an attacker rewriting the domain field MUST be rejected by
        // signature check. Without `domain` in the signed bytes, the
        // attacker could lift Alice's attestation for example.com
        // and re-present it under sidevers.com.
        let side = fixture_side(0x33);
        let mut p = HandleAttestPayload::sign(&side, "alice", "example.com", 1).unwrap();
        // Re-domain — same side, same handle_local, same signature,
        // different domain. The signature is over the (now-stale)
        // example.com domain; from_wire_bytes recomputes the digest
        // with the new domain and rejects.
        p.domain = "sidevers.com".to_owned();
        let bytes = p.to_wire_bytes();
        let err = HandleAttestPayload::from_wire_bytes(&bytes).unwrap_err();
        assert!(
            matches!(err, Error::SignatureInvalid),
            "cross-domain replay must fail signature check, got {err:?}"
        );
    }

    #[test]
    fn page_publish_signed_round_trip() {
        let side = fixture_side(0x33);
        let p = PagePublishPayload::sign(
            &side,
            "about",
            "text/markdown",
            b"# Hello\n".to_vec(),
            1_700_000_000,
        )
        .unwrap();
        let bytes = p.to_wire_bytes();
        let decoded = PagePublishPayload::from_wire_bytes(&bytes).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn page_publish_tamper_breaks_signature() {
        let side = fixture_side(0x44);
        let mut p = PagePublishPayload::sign(&side, "x", "text/plain", b"a".to_vec(), 1).unwrap();
        p.content = b"b".to_vec();
        let bytes = p.to_wire_bytes();
        let err = PagePublishPayload::from_wire_bytes(&bytes).unwrap_err();
        assert!(matches!(err, Error::SignatureInvalid));
    }

    #[test]
    fn page_fetch_round_trip() {
        let p = PageFetchPayload {
            side: [0xAB; PUBLIC_KEY_LEN],
            slug: "bio".to_owned(),
        };
        let bytes = p.encode();
        let decoded = PageFetchPayload::decode(&bytes).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn page_deliver_wraps_page_publish() {
        let side = fixture_side(0x55);
        let inner = PagePublishPayload::sign(
            &side,
            "home",
            "text/html",
            b"<p>hi</p>".to_vec(),
            1_700_000_001,
        )
        .unwrap();
        let p = PageDeliverPayload {
            page: inner.clone(),
        };
        let bytes = p.encode();
        let decoded = PageDeliverPayload::decode(&bytes).unwrap();
        assert_eq!(decoded.page, inner);
    }

    #[test]
    fn announcement_signed_round_trip() {
        let side = fixture_side(0x66);
        let p = AnnouncementPayload::sign(&side, "I exist", 1_700_000_002).unwrap();
        let bytes = p.to_wire_bytes();
        let decoded = AnnouncementPayload::from_wire_bytes(&bytes).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn directory_entry_aggregates_attestations() {
        let side_a = fixture_side(0x77);
        let side_b = fixture_side(0x88);
        let att_a = HandleAttestPayload::sign(&side_a, "team", "sidevers.com", 100).unwrap();
        let att_b = HandleAttestPayload::sign(&side_b, "team", "sidevers.com", 200).unwrap();
        let entry = DirectoryEntryPayload {
            side: side_a.public_bytes(),
            handle: "team@sidevers.com".to_owned(),
            attestations: vec![att_a.clone(), att_b.clone()],
        };
        let bytes = entry.encode();
        let decoded = DirectoryEntryPayload::decode(&bytes).unwrap();
        assert_eq!(decoded.attestations.len(), 2);
        assert_eq!(decoded.attestations[0], att_a);
        assert_eq!(decoded.attestations[1], att_b);
    }
}
