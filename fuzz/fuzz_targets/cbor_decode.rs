//! Fuzz the deterministic-CBOR reader.
//!
//! `CborReader` enforces RFC 8949 §4.2.1 canonical encoding: shortest-form
//! length prefixes, no indefinite-length items, etc. It's the foundation
//! every payload codec sits on top of.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sidevers_core::cbor::CborReader;

fuzz_target!(|data: &[u8]| {
    // Walk the reader through a handful of operations and ensure none panic.
    let mut r = CborReader::new(data);
    let _ = r.read_u64();
    let mut r = CborReader::new(data);
    let _ = r.read_bytes();
    let mut r = CborReader::new(data);
    let _ = r.read_text();
    let mut r = CborReader::new(data);
    let _ = r.read_map_header();
    let mut r = CborReader::new(data);
    let _ = r.read_array_header();
    let mut r = CborReader::new(data);
    let _ = r.read_bool();
    let mut r = CborReader::new(data);
    let _ = r.read_bytes_or_null();
});
