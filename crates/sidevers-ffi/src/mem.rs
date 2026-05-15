//! Memory-management helpers for the FFI boundary.

use std::ffi::CString;
use std::os::raw::c_char;

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
    if ptr.is_null() || len == 0 {
        return;
    }
    // SAFETY: caller contract — `ptr`/`len` came from `vec_to_ffi`.
    unsafe {
        let slice = std::ptr::slice_from_raw_parts_mut(ptr, len);
        drop(Box::from_raw(slice));
    }
}

/// Release a NUL-terminated C string previously returned by a Sidevers FFI
/// function.
///
/// `ptr` MUST be the value originally returned by Sidevers (e.g. by
/// `sv_address_encode` or `sv_last_error_message`). A null pointer is a no-op.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sv_free_string(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    // SAFETY: caller contract — `ptr` came from `CString::into_raw`.
    unsafe {
        drop(CString::from_raw(ptr));
    }
}
