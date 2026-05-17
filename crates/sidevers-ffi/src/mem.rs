//! Memory-management helpers for the FFI boundary.

use std::ffi::CString;
use std::os::raw::c_char;

/// Maximum bytes scanned for the NUL terminator in [`cstr_with_cap`].
/// Any legitimate Sidevers FFI string fits well inside this; the cap
/// turns a non-NUL-terminated C string into a clean error instead of
/// an unbounded scan past the caller's buffer (Audit P2.E).
pub(crate) const FFI_CSTR_MAX_LEN: usize = 4096;

/// Read up to `FFI_CSTR_MAX_LEN` bytes from `ptr` looking for a NUL
/// terminator. Returns the borrowed bytes (excluding the NUL) on
/// success, or `None` if no NUL was found within the cap.
///
/// # Safety
/// `ptr` must be non-null and point to memory readable for whichever
/// is smaller of (a) the byte count up to and including the first NUL
/// and (b) `FFI_CSTR_MAX_LEN` bytes. Standard C-FFI contract.
pub(crate) unsafe fn cstr_with_cap<'a>(ptr: *const c_char) -> Option<&'a [u8]> {
    if ptr.is_null() {
        return None;
    }
    let mut len = 0usize;
    while len < FFI_CSTR_MAX_LEN {
        // SAFETY: caller contract — ptr+len is readable as long as we
        // haven't crossed a NUL yet, which the loop ensures.
        let byte = unsafe { ptr.add(len).read() as u8 };
        if byte == 0 {
            // SAFETY: we have read `len` bytes successfully; the slice
            // from ptr..ptr+len is valid and does not include the NUL.
            return Some(unsafe { std::slice::from_raw_parts(ptr as *const u8, len) });
        }
        len += 1;
    }
    None
}

/// Internal: package a Rust-owned `Vec<u8>` into a `(ptr, len)` pair that
/// transfers ownership across the FFI. Free with [`sv_free_buffer`].
pub(crate) fn vec_to_ffi(v: Vec<u8>) -> (*mut u8, usize) {
    let boxed = v.into_boxed_slice();
    let len = boxed.len();
    let ptr = Box::into_raw(boxed) as *mut u8;
    (ptr, len)
}

/// Internal: package a Rust `String` as a heap-allocated, NUL-terminated
/// C string. Returns null if the string contained interior NULs (caller
/// should treat null as an error). Free with [`sv_free_string`].
pub(crate) fn string_to_ffi(s: String) -> *mut c_char {
    match CString::new(s) {
        Ok(cstr) => cstr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Release a buffer previously returned by a Sidevers FFI function.
///
/// `ptr` MUST be the value originally returned by Sidevers, paired with the
/// `len` returned alongside it. Calling with mismatched arguments is
/// undefined behavior. A null pointer or zero length is a no-op.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sv_free_buffer(ptr: *mut u8, len: usize) {
    // Audit P1.B — swallow any panic at the FFI boundary so we don't
    // unwind across C. `free` is supposed to be infallible from the
    // caller's perspective; a panic here would be a Rust-side bug, not
    // a caller error.
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if ptr.is_null() || len == 0 {
            return;
        }
        // SAFETY: caller contract — `ptr`/`len` came from `vec_to_ffi`.
        unsafe {
            let slice = std::ptr::slice_from_raw_parts_mut(ptr, len);
            drop(Box::from_raw(slice));
        }
    }));
}

/// Release a NUL-terminated C string previously returned by a Sidevers FFI
/// function.
///
/// `ptr` MUST be the value originally returned by Sidevers (e.g. by
/// `sv_address_encode` or `sv_last_error_message`). A null pointer is a no-op.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sv_free_string(ptr: *mut c_char) {
    // Audit P1.B — same reasoning as `sv_free_buffer`.
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if ptr.is_null() {
            return;
        }
        // SAFETY: caller contract — `ptr` came from `CString::into_raw`.
        unsafe {
            drop(CString::from_raw(ptr));
        }
    }));
}
