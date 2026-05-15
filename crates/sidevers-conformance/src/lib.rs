//! Sidevers conformance test harness.
//!
//! Per protocol spec §10.4 and Launch §3.2, the conformance suite is itself
//! a Phase-1 deliverable. The harness grows in three layers:
//!
//!   * **Month 2** (this file): byte-stable encode/decode fixtures and
//!     property tests over the no-I/O surface in `sidevers-core`. If a future
//!     encoder change reorders a map key or stops emitting shortest-form
//!     integers, these tests fail before any signature does.
//!   * **Month 3**: in-process two-node integration over QUIC: handshake,
//!     direct message, storage object fetch.
//!   * **Month 4**: multi-process three-node + relay scenarios; one test per
//!     Appendix-A Phase-1 message type.

// The whole crate is a test harness; allow panic-on-error idioms throughout.
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub mod fixtures;
pub mod harness;
