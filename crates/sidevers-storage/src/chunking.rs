//! Phase 1.C1: large-object chunking.
//!
//! `ObjectStore::put` stores any blob as one object. For multi-megabyte
//! attachments that one-blob-per-object model is awkward — a peer
//! offering a 10 MiB photo would push 10 MiB across the wire as a
//! single frame, with no possibility of partial fetch / resume.
//!
//! This module wraps `ObjectStore` with a chunking codec:
//!
//!   * [`put_chunked`] splits a large blob into fixed-size chunks
//!     (default `CHUNK_MAX = 256 KiB`), stores each as its own
//!     content-addressed object, and writes a small *manifest* object
//!     listing the chunk hashes. The root [`Reference`] returned has
//!     the manifest hash + the per-chunk `Reference`s as `deps`, so
//!     callers can fetch chunks individually if they want partial
//!     transfer.
//!   * [`get_chunked`] reassembles the original bytes by fetching the
//!     manifest, then each chunk in declared order, then concatenating
//!     and hash-verifying the result.
//!
//! Small blobs (`<= CHUNK_MAX`) round-trip through a single put + an
//! empty-deps Reference — chunking adds no overhead until you need it.

use sidevers_core::cbor::{self, CborReader, CborWriter, MapEntry};
use sidevers_core::error::Error as CoreError;
use tracing::warn;

use crate::error::{Error, Result};
use crate::object::{ADDRESS_LEN, ObjectStore};
use crate::reference::Reference;

/// Default chunk size — 256 KiB. Sized to fit in one QUIC datagram-train
/// without forcing huge per-stream buffers, while keeping the manifest
/// reasonable (10 MiB blob → 40 chunk entries × 32 bytes = 1.3 KiB
/// manifest).
pub const CHUNK_MAX: usize = 256 * 1024;

/// MIME type stamped on chunk manifests so peers can distinguish them
/// from real content.
pub const MANIFEST_MIME: &str = "application/sidevers.chunk-manifest+cbor";

/// MIME type for an individual chunk piece.
pub const CHUNK_MIME: &str = "application/sidevers.chunk+binary";

/// MIME type for a small, unchunked blob written via `put_chunked`.
pub const SINGLE_MIME: &str = "application/octet-stream";

/// Store `bytes` content-addressed, splitting into chunks if larger
/// than [`CHUNK_MAX`]. Returns a root [`Reference`] whose `deps` are
/// the per-chunk references when chunking happens, or an empty `deps`
/// for a single-object store.
pub async fn put_chunked(store: &ObjectStore, bytes: Vec<u8>) -> Result<Reference> {
    let total_size = bytes.len() as u64;
    if bytes.len() <= CHUNK_MAX {
        let hash = store.put(bytes).await?;
        return Ok(Reference::new(hash, total_size, SINGLE_MIME));
    }
    // Chunk the bytes.
    let mut chunk_refs = Vec::new();
    let mut chunk_hashes: Vec<[u8; ADDRESS_LEN]> = Vec::new();
    for chunk in bytes.chunks(CHUNK_MAX) {
        let sz = chunk.len() as u64;
        let h = store.put(chunk.to_vec()).await?;
        chunk_refs.push(Reference::new(h, sz, CHUNK_MIME));
        chunk_hashes.push(h);
    }
    let manifest_bytes = encode_manifest(total_size, &chunk_hashes);
    let manifest_hash = store.put(manifest_bytes).await?;
    Ok(Reference {
        hash: manifest_hash,
        size: total_size,
        mime: MANIFEST_MIME.to_owned(),
        hints: Vec::new(),
        deps: chunk_refs,
    })
}

/// Reassemble the bytes a `put_chunked` reference points at. For
/// single-object references this is a single `store.get`; for
/// manifest references this fetches the manifest, decodes it, and
/// concatenates the chunks (verifying each chunk's hash via
/// `ObjectStore::get`).
pub async fn get_chunked(store: &ObjectStore, reference: &Reference) -> Result<Vec<u8>> {
    if reference.mime != MANIFEST_MIME {
        // Single-object — fetch directly.
        return store
            .get(&reference.hash)
            .await?
            .ok_or(Error::HashMismatch {
                expected: hex::encode(reference.hash),
                got: "(missing)".to_owned(),
            });
    }
    // Fetch + decode manifest.
    let manifest_bytes = store
        .get(&reference.hash)
        .await?
        .ok_or(Error::HashMismatch {
            expected: hex::encode(reference.hash),
            got: "(missing manifest)".to_owned(),
        })?;
    let (declared_total, chunk_hashes) = decode_manifest(&manifest_bytes)?;
    if declared_total != reference.size {
        warn!(
            declared = declared_total,
            in_ref = reference.size,
            "chunk manifest size disagrees with reference size; trusting manifest"
        );
    }
    let mut out = Vec::with_capacity(declared_total as usize);
    for h in chunk_hashes {
        let piece = store.get(&h).await?.ok_or(Error::HashMismatch {
            expected: hex::encode(h),
            got: "(missing chunk)".to_owned(),
        })?;
        out.extend_from_slice(&piece);
    }
    // Phase 1.C1 (audit-pass M1): sanity-check that the assembled
    // bytes match the manifest's declared length. Per-chunk hashes
    // are verified by ObjectStore::get (§5.4 mandate) but the
    // manifest's `total_size` field itself isn't part of that check.
    // A manifest whose chunks sum to a different total than declared
    // is malformed; reject rather than silently returning surprising
    // bytes.
    if out.len() as u64 != declared_total {
        return Err(Error::HashMismatch {
            expected: format!("{declared_total} bytes (per manifest)"),
            got: format!("{} bytes (per chunks)", out.len()),
        });
    }
    Ok(out)
}

fn encode_manifest(total_size: u64, chunks: &[[u8; ADDRESS_LEN]]) -> Vec<u8> {
    // CBOR canonical key order (RFC 8949 §4.2.1):
    //   "chunks" (6 chars) < "total_size" (10 chars)
    let mut chunks_array = CborWriter::new();
    chunks_array.write_array_header(chunks.len());
    for h in chunks {
        chunks_array.write_bytes(h);
    }
    let entries = [
        MapEntry {
            key: cbor::key("chunks"),
            value: chunks_array.into_bytes(),
        },
        MapEntry {
            key: cbor::key("total_size"),
            value: cbor::uint(total_size),
        },
    ];
    cbor::encode_map(&entries)
}

fn decode_manifest(bytes: &[u8]) -> std::result::Result<(u64, Vec<[u8; ADDRESS_LEN]>), CoreError> {
    let mut r = CborReader::new(bytes);
    let n = r.read_map_header()?;
    if n != 2 {
        return Err(CoreError::CborDecode(format!(
            "chunk manifest expected 2 keys, got {n}"
        )));
    }
    if r.read_text()? != "chunks" {
        return Err(CoreError::CborNotCanonical("chunk manifest: key order"));
    }
    let len = r.read_array_header()?;
    let mut chunks = Vec::with_capacity(len);
    for _ in 0..len {
        let b = r.read_bytes()?;
        if b.len() != ADDRESS_LEN {
            return Err(CoreError::BadFieldLength {
                field: "chunk.hash",
                expected: ADDRESS_LEN,
                got: b.len(),
            });
        }
        let mut arr = [0u8; ADDRESS_LEN];
        arr.copy_from_slice(b);
        chunks.push(arr);
    }
    if r.read_text()? != "total_size" {
        return Err(CoreError::CborNotCanonical("chunk manifest: key order"));
    }
    let total_size = r.read_u64()?;
    if !r.at_end() {
        return Err(CoreError::CborDecode(
            "trailing bytes after manifest".into(),
        ));
    }
    Ok((total_size, chunks))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn small_blob_round_trips_without_chunking() {
        let tmp = TempDir::new().unwrap();
        let store = ObjectStore::open(tmp.path()).await.unwrap();
        let payload = b"small bytes".to_vec();
        let r = put_chunked(&store, payload.clone()).await.unwrap();
        assert_eq!(r.mime, SINGLE_MIME);
        assert!(r.deps.is_empty());
        let got = get_chunked(&store, &r).await.unwrap();
        assert_eq!(got, payload);
    }

    #[tokio::test]
    async fn large_blob_chunks_and_reassembles() {
        let tmp = TempDir::new().unwrap();
        let store = ObjectStore::open(tmp.path()).await.unwrap();
        // 600 KiB → 3 chunks at default CHUNK_MAX.
        let big: Vec<u8> = (0..600_000).map(|i| (i & 0xFF) as u8).collect();
        let r = put_chunked(&store, big.clone()).await.unwrap();
        assert_eq!(r.mime, MANIFEST_MIME);
        assert_eq!(r.deps.len(), 3);
        // Total size matches.
        assert_eq!(r.size, 600_000);
        // Each chunk is independently fetchable + correct.
        for dep in &r.deps {
            assert!(store.has(&dep.hash).await.unwrap());
        }
        let got = get_chunked(&store, &r).await.unwrap();
        assert_eq!(got, big);
    }

    #[tokio::test]
    async fn manifest_length_mismatch_is_rejected() {
        // Audit-pass M1: forge a manifest whose declared total_size
        // doesn't match the chunks' actual byte sum. `get_chunked`
        // must error rather than silently returning surprising bytes.
        let tmp = TempDir::new().unwrap();
        let store = ObjectStore::open(tmp.path()).await.unwrap();
        // Two 10-byte chunks → real total 20 bytes; but we'll declare 999.
        let chunk_a_hash = store.put(vec![0xAAu8; 10]).await.unwrap();
        let chunk_b_hash = store.put(vec![0xBBu8; 10]).await.unwrap();
        let forged_manifest = encode_manifest(999, &[chunk_a_hash, chunk_b_hash]);
        let manifest_hash = store.put(forged_manifest).await.unwrap();
        let forged_ref = Reference {
            hash: manifest_hash,
            size: 999,
            mime: MANIFEST_MIME.to_owned(),
            hints: Vec::new(),
            deps: Vec::new(),
        };
        let err = get_chunked(&store, &forged_ref).await.unwrap_err();
        assert!(
            matches!(err, crate::error::Error::HashMismatch { .. }),
            "expected HashMismatch on length disagreement, got {err:?}"
        );
    }

    #[tokio::test]
    async fn exactly_chunk_max_does_not_chunk() {
        let tmp = TempDir::new().unwrap();
        let store = ObjectStore::open(tmp.path()).await.unwrap();
        let edge = vec![0xCC; CHUNK_MAX];
        let r = put_chunked(&store, edge.clone()).await.unwrap();
        assert_eq!(r.mime, SINGLE_MIME);
        assert!(r.deps.is_empty());
        let got = get_chunked(&store, &r).await.unwrap();
        assert_eq!(got, edge);
    }
}
