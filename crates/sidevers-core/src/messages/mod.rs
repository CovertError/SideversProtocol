//! Typed payload codecs for the protocol's message types.
//!
//! Each submodule covers one Appendix-A range:
//!
//!   * `direct` — 0x20–0x2F (this file, Month 2).
//!   * Handshake (0x10–0x12), storage (0x30–0x35), and discovery (0x40–0x45)
//!     payloads land in months 3 and 4 alongside their network handlers.
//!
//! Payloads are encoded as CBOR maps in canonical key order (§3.1) and then
//! wrapped (and, for unicast, encrypted) inside an `Envelope` (see `envelope.rs`).

pub mod device;
pub mod direct;
pub mod forward;
pub mod handshake;
pub mod peer;
pub mod profile;
pub mod public;
pub mod rendezvous;
pub mod retirement;
pub mod storage_prefs;
pub mod verse;
