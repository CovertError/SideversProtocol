#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let _ = sidevers_core::messages::retirement::SideRetirementPayload::from_wire_bytes(data);
});
