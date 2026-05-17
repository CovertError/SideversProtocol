//! Contact-card FFI: encode and parse the `sidevers-contact:1:<base32>`
//! invite URI used to bootstrap a peer that has no contacts yet.
//!
//! Sidevers is fundamentally peer-to-peer — once two nodes can dial each
//! other, no server sits in their conversation. But two cold-start users
//! still need *some* way to exchange the first address. The contact card
//! is that primitive: a base32-encoded URI carrying the side public key,
//! a dial address (host:port to connect to), and optional UI hints
//! (display name, side label). Share it as a QR, a deep link, an SMS, or
//! any other out-of-band channel; the scheme is short enough to fit in a
//! v1 QR with comfortable error correction.
//!
//! These two functions plus `sv_dm_seal_text` / `sv_dm_open_text` close
//! the bootstrap-from-zero gap: a fresh client can now generate its own
//! address (`sv_keygen_master` + `sv_derive_side`), publish a contact
//! card to a friend out-of-band, scan one back, and send the first DM —
//! without any Sidevers-operated server in the path.

use std::os::raw::c_char;

use sidevers_core::ContactCard;

use crate::error::{SvStatus, clear_last_error, ffi_entry, set_last_error, status_from};
use crate::mem::{cstr_with_cap, string_to_ffi};

/// 32 bytes — Ed25519 side public key.
const SIDE_KEY_LEN: usize = 32;

/// Maximum lengths mirror the parser limits in
/// `sidevers_core::messages::device` (`CONTACT_DIAL_ADDR_MAX`,
/// `CONTACT_DISPLAY_NAME_MAX`, `CONTACT_SIDE_LABEL_MAX`). The encode side
/// in core does not validate, so the FFI does — otherwise a caller could
/// produce a URI that nothing on Earth can parse.
const FFI_DIAL_ADDR_MAX: usize = 256;
const FFI_DISPLAY_NAME_MAX: usize = 512;
const FFI_SIDE_LABEL_MAX: usize = 64;

/// Encode a contact-card invite URI (`sidevers-contact:1:<base32>`).
///
/// Inputs:
///   * `side_32` — the inviter's side public key (Ed25519, 32 bytes). Required.
///   * `dial_addr` — NUL-terminated UTF-8 host:port the friend's client should dial
///     (e.g. `"203.0.113.5:4242"`). Required, 1–256 bytes.
///   * `display_name` — NUL-terminated UTF-8 hint shown on first encounter, or
///     `NULL` to omit. Max 512 bytes.
///   * `side_label` — NUL-terminated UTF-8 context hint (e.g. `"work"`), or
///     `NULL` to omit. Max 64 bytes.
///
/// Output:
///   * `*out_uri` — heap-allocated NUL-terminated C string. Free with
///     [`sv_free_string`](crate::sv_free_string).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sv_contact_card_encode(
    side_32: *const u8,
    dial_addr: *const c_char,
    display_name: *const c_char,
    side_label: *const c_char,
    out_uri: *mut *mut c_char,
) -> SvStatus {
    ffi_entry("sv_contact_card_encode", || {
        if side_32.is_null() || dial_addr.is_null() || out_uri.is_null() {
            set_last_error(
                "sv_contact_card_encode: null pointer argument (side_32, dial_addr, out_uri are required)",
            );
            return SvStatus::NullPtr;
        }

        // SAFETY: caller contract — side_32 is a readable 32-byte buffer.
        let side_slice = unsafe { std::slice::from_raw_parts(side_32, SIDE_KEY_LEN) };
        let mut side = [0u8; SIDE_KEY_LEN];
        side.copy_from_slice(side_slice);

        let dial = match read_required_string(dial_addr, "dial_addr", FFI_DIAL_ADDR_MAX) {
            Ok(s) => s,
            Err(status) => return status,
        };
        if dial.is_empty() {
            set_last_error("sv_contact_card_encode: dial_addr is empty");
            return SvStatus::InvalidInput;
        }

        let display = match read_optional_string(display_name, "display_name", FFI_DISPLAY_NAME_MAX)
        {
            Ok(s) => s,
            Err(status) => return status,
        };
        let label = match read_optional_string(side_label, "side_label", FFI_SIDE_LABEL_MAX) {
            Ok(s) => s,
            Err(status) => return status,
        };

        let card = ContactCard {
            side,
            dial_addr: dial,
            display_name: display,
            side_label: label,
        };
        let uri = card.encode();
        let c_uri = string_to_ffi(uri);
        if c_uri.is_null() {
            // Base32-only URI cannot contain an interior NUL; this is an
            // invariant violation, not bad input.
            set_last_error(
                "sv_contact_card_encode: encoded URI contained interior NUL (invariant)",
            );
            return SvStatus::Internal;
        }
        // SAFETY: caller contract — out_uri is writable.
        unsafe {
            std::ptr::write(out_uri, c_uri);
        }
        clear_last_error();
        SvStatus::Ok
    })
}

/// Parse a contact-card invite URI back into its fields.
///
/// Inputs:
///   * `uri` — NUL-terminated UTF-8 `"sidevers-contact:1:<base32>"`.
///
/// Outputs (all required pointers):
///   * `out_side_32` — writable 32-byte buffer for the inviter's side pubkey.
///   * `*out_dial_addr` — heap-allocated NUL-terminated C string, always set on success.
///   * `*out_display_name` — heap-allocated NUL-terminated C string, OR `NULL` if the
///     URI did not include a display name.
///   * `*out_side_label` — heap-allocated NUL-terminated C string, OR `NULL` if the
///     URI did not include a side label.
///
/// Each non-NULL returned string must be freed with [`sv_free_string`](crate::sv_free_string).
/// On error, no outputs are modified.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sv_contact_card_parse(
    uri: *const c_char,
    out_side_32: *mut u8,
    out_dial_addr: *mut *mut c_char,
    out_display_name: *mut *mut c_char,
    out_side_label: *mut *mut c_char,
) -> SvStatus {
    ffi_entry("sv_contact_card_parse", || {
        if uri.is_null()
            || out_side_32.is_null()
            || out_dial_addr.is_null()
            || out_display_name.is_null()
            || out_side_label.is_null()
        {
            set_last_error("sv_contact_card_parse: null pointer argument");
            return SvStatus::NullPtr;
        }

        // SAFETY: caller contract — uri is NUL-terminated.
        let uri_bytes = match unsafe { cstr_with_cap(uri) } {
            Some(b) => b,
            None => {
                set_last_error("sv_contact_card_parse: uri not NUL-terminated within length cap");
                return SvStatus::InvalidInput;
            }
        };
        let uri_str = match std::str::from_utf8(uri_bytes) {
            Ok(s) => s,
            Err(_) => {
                set_last_error("sv_contact_card_parse: uri is not valid UTF-8");
                return SvStatus::InvalidInput;
            }
        };

        let (status, parsed) = status_from(ContactCard::parse(uri_str));
        let card = match parsed {
            Some(c) => c,
            None => return status,
        };

        // Convert all three output strings up-front so the function is
        // atomic: either every output is written, or none is. If a string
        // can't be turned into a C string (interior NUL), free whatever
        // we already allocated before returning.
        let dial_ptr = string_to_ffi(card.dial_addr);
        if dial_ptr.is_null() {
            set_last_error("sv_contact_card_parse: dial_addr contained interior NUL");
            return SvStatus::Decode;
        }
        let display_ptr = match card.display_name {
            None => std::ptr::null_mut(),
            Some(s) => {
                let p = string_to_ffi(s);
                if p.is_null() {
                    // SAFETY: dial_ptr was just allocated via CString::into_raw.
                    unsafe {
                        drop(std::ffi::CString::from_raw(dial_ptr));
                    }
                    set_last_error("sv_contact_card_parse: display_name contained interior NUL");
                    return SvStatus::Decode;
                }
                p
            }
        };
        let label_ptr = match card.side_label {
            None => std::ptr::null_mut(),
            Some(s) => {
                let p = string_to_ffi(s);
                if p.is_null() {
                    // SAFETY: both pointers came from CString::into_raw.
                    unsafe {
                        drop(std::ffi::CString::from_raw(dial_ptr));
                        if !display_ptr.is_null() {
                            drop(std::ffi::CString::from_raw(display_ptr));
                        }
                    }
                    set_last_error("sv_contact_card_parse: side_label contained interior NUL");
                    return SvStatus::Decode;
                }
                p
            }
        };

        // SAFETY: caller contract — all output pointers are writable; side
        // pubkey is 32 bytes; string pointers are valid until freed.
        unsafe {
            std::ptr::copy_nonoverlapping(card.side.as_ptr(), out_side_32, SIDE_KEY_LEN);
            std::ptr::write(out_dial_addr, dial_ptr);
            std::ptr::write(out_display_name, display_ptr);
            std::ptr::write(out_side_label, label_ptr);
        }
        SvStatus::Ok
    })
}

/// Shared validation: read a NUL-terminated C string, check the length
/// cap, and return an owned `String`. Sets the last-error message on
/// failure with a field-named prefix.
fn read_required_string(
    ptr: *const c_char,
    field: &'static str,
    max_len: usize,
) -> Result<String, SvStatus> {
    // SAFETY: caller already null-checked.
    let bytes = match unsafe { cstr_with_cap(ptr) } {
        Some(b) => b,
        None => {
            set_last_error(format!(
                "sv_contact_card_encode: {field} not NUL-terminated within length cap"
            ));
            return Err(SvStatus::InvalidInput);
        }
    };
    if bytes.len() > max_len {
        set_last_error(format!(
            "sv_contact_card_encode: {field} too long ({} > {max_len})",
            bytes.len()
        ));
        return Err(SvStatus::InvalidInput);
    }
    let s = match std::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => {
            set_last_error(format!(
                "sv_contact_card_encode: {field} is not valid UTF-8"
            ));
            return Err(SvStatus::InvalidInput);
        }
    };
    Ok(s.to_owned())
}

/// Optional version: returns `Ok(None)` for a null pointer, otherwise
/// delegates to `read_required_string`.
fn read_optional_string(
    ptr: *const c_char,
    field: &'static str,
    max_len: usize,
) -> Result<Option<String>, SvStatus> {
    if ptr.is_null() {
        return Ok(None);
    }
    read_required_string(ptr, field, max_len).map(Some)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::ffi::{CStr, CString};

    fn cstr(s: &str) -> CString {
        CString::new(s).expect("test fixture must not contain NUL")
    }

    /// Helper: free a `*mut c_char` returned by the FFI (test-only — in
    /// production the caller would use `sv_free_string`).
    unsafe fn free_c_str(p: *mut c_char) {
        if !p.is_null() {
            // SAFETY: pointer came from CString::into_raw via string_to_ffi.
            unsafe {
                drop(CString::from_raw(p));
            }
        }
    }

    #[test]
    fn encode_then_parse_round_trips_all_fields() {
        let side = [0x11u8; SIDE_KEY_LEN];
        let dial = cstr("203.0.113.5:4242");
        let name = cstr("Omar");
        let label = cstr("work");

        let mut uri_ptr: *mut c_char = std::ptr::null_mut();
        let status = unsafe {
            sv_contact_card_encode(
                side.as_ptr(),
                dial.as_ptr(),
                name.as_ptr(),
                label.as_ptr(),
                &mut uri_ptr,
            )
        };
        assert_eq!(status, SvStatus::Ok);
        assert!(!uri_ptr.is_null());
        let uri = unsafe { CStr::from_ptr(uri_ptr) }.to_str().unwrap();
        assert!(uri.starts_with("sidevers-contact:1:"));

        let mut out_side = [0u8; SIDE_KEY_LEN];
        let mut out_dial: *mut c_char = std::ptr::null_mut();
        let mut out_name: *mut c_char = std::ptr::null_mut();
        let mut out_label: *mut c_char = std::ptr::null_mut();
        let status = unsafe {
            sv_contact_card_parse(
                uri_ptr,
                out_side.as_mut_ptr(),
                &mut out_dial,
                &mut out_name,
                &mut out_label,
            )
        };
        assert_eq!(status, SvStatus::Ok);
        assert_eq!(out_side, side);
        assert_eq!(
            unsafe { CStr::from_ptr(out_dial) }.to_str().unwrap(),
            "203.0.113.5:4242"
        );
        assert_eq!(
            unsafe { CStr::from_ptr(out_name) }.to_str().unwrap(),
            "Omar"
        );
        assert_eq!(
            unsafe { CStr::from_ptr(out_label) }.to_str().unwrap(),
            "work"
        );

        unsafe {
            free_c_str(uri_ptr);
            free_c_str(out_dial);
            free_c_str(out_name);
            free_c_str(out_label);
        }
    }

    #[test]
    fn encode_without_optional_fields_parses_back_with_nulls() {
        let side = [0x22u8; SIDE_KEY_LEN];
        let dial = cstr("[2001:db8::1]:4242");

        let mut uri_ptr: *mut c_char = std::ptr::null_mut();
        let status = unsafe {
            sv_contact_card_encode(
                side.as_ptr(),
                dial.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                &mut uri_ptr,
            )
        };
        assert_eq!(status, SvStatus::Ok);

        let mut out_side = [0u8; SIDE_KEY_LEN];
        let mut out_dial: *mut c_char = std::ptr::null_mut();
        let mut out_name: *mut c_char = std::ptr::null_mut();
        let mut out_label: *mut c_char = std::ptr::null_mut();
        let status = unsafe {
            sv_contact_card_parse(
                uri_ptr,
                out_side.as_mut_ptr(),
                &mut out_dial,
                &mut out_name,
                &mut out_label,
            )
        };
        assert_eq!(status, SvStatus::Ok);
        assert_eq!(out_side, side);
        assert_eq!(
            unsafe { CStr::from_ptr(out_dial) }.to_str().unwrap(),
            "[2001:db8::1]:4242"
        );
        // Optional fields must come back as null pointers.
        assert!(out_name.is_null());
        assert!(out_label.is_null());

        unsafe {
            free_c_str(uri_ptr);
            free_c_str(out_dial);
        }
    }

    #[test]
    fn encode_rejects_null_required_inputs() {
        let mut uri_ptr: *mut c_char = std::ptr::null_mut();
        let dial = cstr("127.0.0.1:1");
        let side = [0u8; SIDE_KEY_LEN];

        let s = unsafe {
            sv_contact_card_encode(
                std::ptr::null(),
                dial.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                &mut uri_ptr,
            )
        };
        assert_eq!(s, SvStatus::NullPtr);

        let s = unsafe {
            sv_contact_card_encode(
                side.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                &mut uri_ptr,
            )
        };
        assert_eq!(s, SvStatus::NullPtr);

        let s = unsafe {
            sv_contact_card_encode(
                side.as_ptr(),
                dial.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(s, SvStatus::NullPtr);
    }

    #[test]
    fn encode_rejects_empty_dial_addr() {
        let side = [0u8; SIDE_KEY_LEN];
        let dial = cstr("");
        let mut uri_ptr: *mut c_char = std::ptr::null_mut();
        let s = unsafe {
            sv_contact_card_encode(
                side.as_ptr(),
                dial.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                &mut uri_ptr,
            )
        };
        assert_eq!(s, SvStatus::InvalidInput);
    }

    #[test]
    fn encode_rejects_oversized_dial_addr() {
        let side = [0u8; SIDE_KEY_LEN];
        // 257 chars — one over the cap.
        let dial = cstr(&"a".repeat(FFI_DIAL_ADDR_MAX + 1));
        let mut uri_ptr: *mut c_char = std::ptr::null_mut();
        let s = unsafe {
            sv_contact_card_encode(
                side.as_ptr(),
                dial.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                &mut uri_ptr,
            )
        };
        assert_eq!(s, SvStatus::InvalidInput);
    }

    #[test]
    fn parse_rejects_garbage_uri() {
        let bogus = cstr("https://example.com");
        let mut side = [0u8; SIDE_KEY_LEN];
        let mut a: *mut c_char = std::ptr::null_mut();
        let mut b: *mut c_char = std::ptr::null_mut();
        let mut c: *mut c_char = std::ptr::null_mut();
        let s = unsafe {
            sv_contact_card_parse(bogus.as_ptr(), side.as_mut_ptr(), &mut a, &mut b, &mut c)
        };
        assert_ne!(s, SvStatus::Ok);
        // None of the outputs should be touched on error.
        assert!(a.is_null());
        assert!(b.is_null());
        assert!(c.is_null());
        assert_eq!(side, [0u8; SIDE_KEY_LEN]);
    }

    #[test]
    fn parse_rejects_null_inputs() {
        let mut side = [0u8; SIDE_KEY_LEN];
        let mut a: *mut c_char = std::ptr::null_mut();
        let mut b: *mut c_char = std::ptr::null_mut();
        let mut c: *mut c_char = std::ptr::null_mut();
        let s = unsafe {
            sv_contact_card_parse(std::ptr::null(), side.as_mut_ptr(), &mut a, &mut b, &mut c)
        };
        assert_eq!(s, SvStatus::NullPtr);
    }

    #[test]
    fn flipping_a_uri_byte_breaks_parsing() {
        // Build a valid URI, mangle the base32 body, expect parse failure.
        let side = [0x33u8; SIDE_KEY_LEN];
        let dial = cstr("198.51.100.7:9000");
        let mut uri_ptr: *mut c_char = std::ptr::null_mut();
        unsafe {
            sv_contact_card_encode(
                side.as_ptr(),
                dial.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                &mut uri_ptr,
            )
        };
        let mut uri = unsafe { CStr::from_ptr(uri_ptr) }
            .to_str()
            .unwrap()
            .to_owned();
        // Replace the last base32 char with a non-base32 char ('1' is not in the alphabet).
        let last = uri.len() - 1;
        uri.replace_range(last..last + 1, "1");
        let tampered = cstr(&uri);

        let mut out_side = [0u8; SIDE_KEY_LEN];
        let mut a: *mut c_char = std::ptr::null_mut();
        let mut b: *mut c_char = std::ptr::null_mut();
        let mut c: *mut c_char = std::ptr::null_mut();
        let s = unsafe {
            sv_contact_card_parse(
                tampered.as_ptr(),
                out_side.as_mut_ptr(),
                &mut a,
                &mut b,
                &mut c,
            )
        };
        assert_ne!(s, SvStatus::Ok);

        unsafe { free_c_str(uri_ptr) };
    }
}
