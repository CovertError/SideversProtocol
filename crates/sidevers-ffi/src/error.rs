//! Status codes + thread-local error reporting for the FFI.

use std::cell::RefCell;
use std::ffi::CString;

/// FFI status codes. `SvStatus::Ok` is 0; all errors are negative integers.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SvStatus {
    /// Success.
    Ok = 0,
    /// A required pointer argument was null.
    NullPtr = -1,
    /// An input argument was malformed (wrong length, invalid UTF-8, etc.).
    InvalidInput = -2,
    /// A cryptographic operation failed (signature did not verify, decryption
    /// failed, etc.).
    Crypto = -3,
    /// A decode operation failed (bad CBOR, bad bech32, etc.).
    Decode = -4,
    /// An internal invariant was violated. Indicates a bug.
    Internal = -5,
    /// The OS CSPRNG is unavailable.
    CsprngUnavailable = -6,
    /// A Rust panic was caught at the FFI boundary. Indicates a bug; the
    /// process is in a defined state but the operation did not complete.
    /// (Audit P1.B: panics that unwind across a C-ABI boundary are UB; this
    /// status lets the caller see the failure instead of corrupting state.)
    Panic = -7,
}

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

/// Set the last error message for the current thread. The message is owned
/// (allocated when retrieved).
pub(crate) fn set_last_error(msg: impl Into<String>) {
    let s = msg.into();
    let cstr = CString::new(s).unwrap_or_else(|_| {
        CString::new("error message contained internal NUL").unwrap_or_default()
    });
    LAST_ERROR.with(|cell| cell.replace(Some(cstr)));
}

/// Clear the last error.
pub(crate) fn clear_last_error() {
    LAST_ERROR.with(|cell| cell.replace(None));
}

/// Retrieve the last error message for the current thread, if any.
///
/// Returns a heap-allocated UTF-8 C string (NUL-terminated). Caller MUST
/// free it with [`sv_free_string`](crate::sv_free_string). Returns null
/// if there is no error.
#[unsafe(no_mangle)]
pub extern "C" fn sv_last_error_message() -> *mut std::os::raw::c_char {
    // Audit P1.B — wrap in catch_unwind. A CString clone could panic on
    // allocation failure; that must not unwind across the C boundary.
    match std::panic::catch_unwind(|| {
        LAST_ERROR.with(|cell| match cell.borrow().as_ref() {
            Some(s) => s.clone().into_raw(),
            None => std::ptr::null_mut(),
        })
    }) {
        Ok(p) => p,
        Err(_) => std::ptr::null_mut(),
    }
}

/// Wrap an FFI entry-point body in `catch_unwind` so a panic inside the
/// Rust side cannot unwind across the C-ABI boundary (Audit P1.B). On
/// panic, returns `SvStatus::Panic` and sets the last-error message;
/// the caller's state is intact (modulo whatever partial work the
/// closure did before panicking).
///
/// Uses `AssertUnwindSafe` because most FFI bodies touch `&mut` state
/// (last-error thread-local, output pointers) that isn't `UnwindSafe`
/// in the auto-trait sense. We accept that responsibility: every panic
/// path here is treated as "the operation failed; caller's outputs are
/// not trustworthy" — which is exactly what the `SvStatus::Panic`
/// return code signals.
pub(crate) fn ffi_entry<F>(name: &'static str, body: F) -> SvStatus
where
    F: FnOnce() -> SvStatus,
{
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)) {
        Ok(status) => status,
        Err(_) => {
            set_last_error(format!(
                "{name}: panicked at FFI boundary (caught — state may be incomplete)"
            ));
            SvStatus::Panic
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_entry_passes_through_normal_returns() {
        let s = ffi_entry("test", || SvStatus::Ok);
        assert_eq!(s, SvStatus::Ok);
        let s = ffi_entry("test", || SvStatus::InvalidInput);
        assert_eq!(s, SvStatus::InvalidInput);
    }

    #[test]
    fn ffi_entry_catches_panic_and_returns_panic_status() {
        let s = ffi_entry("test", || {
            panic!("simulated FFI-body panic");
        });
        assert_eq!(s, SvStatus::Panic);
    }

    #[test]
    fn ffi_entry_panic_path_sets_last_error_message() {
        let _ = ffi_entry("named_test_fn", || {
            panic!("kaboom");
        });
        LAST_ERROR.with(|cell| {
            let borrowed = cell.borrow();
            let msg = borrowed.as_ref().expect("error message must be set");
            let s = msg.to_str().unwrap();
            assert!(s.contains("named_test_fn"));
            assert!(s.contains("panicked"));
        });
    }
}

/// Convert a Rust `Result` into an `SvStatus`, setting the last-error
/// message on failure.
pub(crate) fn status_from<T>(r: Result<T, sidevers_core::Error>) -> (SvStatus, Option<T>) {
    match r {
        Ok(v) => {
            clear_last_error();
            (SvStatus::Ok, Some(v))
        }
        Err(e) => {
            use sidevers_core::Error::*;
            let status = match &e {
                SignatureInvalid | DecryptionFailed => SvStatus::Crypto,
                CborEncode(_) | CborDecode(_) | CborNotCanonical(_) => SvStatus::Decode,
                Address(_) => SvStatus::Decode,
                CsprngUnavailable(_) => SvStatus::CsprngUnavailable,
                BadFieldLength { .. }
                | TimestampSkewed { .. }
                | Replay
                | UnsupportedVersion { .. }
                | UnknownType(_) => SvStatus::InvalidInput,
                Invariant(_) => SvStatus::Internal,
            };
            set_last_error(e.to_string());
            (status, None)
        }
    }
}
