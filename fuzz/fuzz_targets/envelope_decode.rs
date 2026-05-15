//! Fuzz the signed-envelope decoder.
//!
//! `Envelope::from_wire_bytes` is the entry point for every received
//! message on the network. It parses CBOR, enforces canonical encoding,
//! reconstructs the to-be-signed bytes, and verifies the Ed25519 signature.
//! All four can be attacked with malformed inputs; any panic here is a
//! protocol-level DoS vulnerability.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sidevers_core::Envelope;

fuzz_target!(|data: &[u8]| {
    // The decoder must NEVER panic on arbitrary input. Errors are fine —
    // they're the documented failure mode. Panics are bugs.
    let _ = Envelope::from_wire_bytes(data);
});
