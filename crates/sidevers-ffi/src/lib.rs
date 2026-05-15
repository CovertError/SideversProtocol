//! Sidevers FFI — C-ABI bindings for the protocol's core operations.
//!
//! This crate exposes the **mobile-lite-mode** surface (per Launch §3.6): key
//! generation, address codec, envelope sign/verify, DM seal/open, linkage
//! proofs. Network operations (handshake, storage protocol, gossip) are NOT
//! exposed here — Phase 3 mobile clients connect to a paired desktop or
//! hosted node over QUIC for those.
//!
//! ## Memory ownership
//!
//! - Buffers passed *into* the FFI are borrowed; the FFI never frees them.
//! - Buffers and strings returned *from* the FFI are heap-allocated and
//!   transfer ownership to the caller. Release with [`sv_free_buffer`] or
//!   [`sv_free_string`].
//!
//! ## Error reporting
//!
//! Every function returns an [`SvStatus`] code. On non-zero return, a
//! thread-local error message is set; retrieve it with [`sv_last_error_message`]
//! (which transfers ownership of the returned C string — free with
//! [`sv_free_string`]).

#![allow(non_camel_case_types)]
// Panics here are bugs, not normal flow. Inside FFI functions we use
// `catch_unwind` to avoid unwinding across the C ABI.
#![allow(clippy::missing_safety_doc)]

mod address;
mod dm;
mod error;
mod keys;
mod linkage;
mod mem;

pub use address::*;
pub use dm::*;
pub use error::*;
pub use keys::*;
pub use linkage::*;
pub use mem::*;
