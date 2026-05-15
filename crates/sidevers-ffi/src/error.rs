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
    LAST_ERROR.with(|cell| match cell.borrow().as_ref() {
        Some(s) => s.clone().into_raw(),
        None => std::ptr::null_mut(),
    })
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
