//! Sidevers protocol core.
//!
//! Implements the no-I/O layers of the Sidevers v1 protocol spec:
//! identity (§2), the signed CBOR envelope (§3), payload encryption (§3.4),
//! and linkage proofs (§2.7). No sockets, no filesystem, no async runtime.

#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod address;
pub mod cbor;
pub mod envelope;
pub mod error;
pub mod keys;
pub mod linkage;
pub mod messages;
pub mod payload;
pub mod replay;
pub mod verse;

pub use address::{Address, AddressKind};
pub use envelope::{Envelope, MessageType, PROTOCOL_VERSION};
pub use error::{Error, Result};
pub use keys::{MasterKey, SideKey, SideLabel};
