//! Fuzz the DirectMessage payload decoder — the most-touched payload codec
//! on the network.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sidevers_core::messages::direct::DirectMessagePayload;

fuzz_target!(|data: &[u8]| {
    let _ = DirectMessagePayload::decode(data);
});
