//! Sidevers content-addressed object storage.
//!
//! Implements the storage half of protocol spec §5: objects addressed by
//! their BLAKE3 hash, with hash-on-fetch verification (§5.4) mandatory on
//! every read.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod chunking;
mod db;
pub mod error;
pub mod object;
pub mod reference;

pub use chunking::{CHUNK_MAX, CHUNK_MIME, MANIFEST_MIME, SINGLE_MIME, get_chunked, put_chunked};
pub use error::{Error, Result};
pub use object::{ADDRESS_LEN, INLINE_MAX, ObjectStore};
pub use reference::Reference;
