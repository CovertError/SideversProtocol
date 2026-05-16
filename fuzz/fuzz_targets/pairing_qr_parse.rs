#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    // PairingQr::parse takes &str; coerce arbitrary bytes via from_utf8
    // (invalid utf-8 is just discarded — parse path isn't reached for
    // those, but UTF-8 valid garbage still exercises the URI scanner).
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = sidevers_core::PairingQr::parse(s);
    }
});
