#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let _ = sidevers_core::PageDeliverPayload::decode(data);
});
