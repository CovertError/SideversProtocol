#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    // VerseReconsentPayload only exposes a verifying decoder. The
    // signature check will fail against a zero pubkey for almost all
    // inputs — that's fine; we're hunting parser panics, not valid
    // payloads.
    let pk = [0u8; 32];
    let _ = sidevers_core::messages::verse::VerseReconsentPayload::decode_and_verify(data, &pk);
});
