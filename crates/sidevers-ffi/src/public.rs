//! Public-layer FFI: verify-side codecs and a generic Ed25519 verifier.
//!
//! The Rust node ships the public-layer wire codecs (`HandleAttest`,
//! `PagePublish`, etc.) but no `serve_public` handler — Phase 2 of the
//! protocol roadmap is the Laravel-side `sidevers.com` registry. This
//! module is the FFI surface that lets that registry verify wire payloads
//! against `libsidevers` instead of reimplementing CBOR + Ed25519 +
//! BLAKE3 in PHP.
//!
//! Only the *verify* (and one composite *encode*) operations live here:
//! the registry never holds user seeds, so the *sign* side stays in the
//! desktop / mobile clients that own the keys.

use std::os::raw::c_char;

use sidevers_core::keys::{PUBLIC_KEY_LEN, PublicKey, SIGNATURE_LEN};
use sidevers_core::{DirectoryEntryPayload, HandleAttestPayload, PagePublishPayload};

use crate::error::{SvStatus, clear_last_error, ffi_entry, set_last_error, status_from};
use crate::mem::cstr_with_cap;
use crate::mem::string_to_ffi;
use crate::mem::vec_to_ffi;

/// Verify a `HandleAttestPayload` wire encoding and extract the side public
/// key, the claimed handle, and the issued-at timestamp.
///
/// Inputs:
///   * `wire_ptr`, `wire_len` — the CBOR-encoded HandleAttest bytes.
///
/// Outputs (all required):
///   * `out_side_pk_32` — writable 32-byte buffer for the claiming side's pubkey.
///   * `*out_handle` — heap-allocated NUL-terminated C string with the handle.
///     Free with [`sv_free_string`](crate::sv_free_string).
///   * `out_issued_at` — writable u64.
///
/// On error, no outputs are modified.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sv_handle_attest_verify(
    wire_ptr: *const u8,
    wire_len: usize,
    out_side_pk_32: *mut u8,
    out_handle: *mut *mut c_char,
    out_issued_at: *mut u64,
) -> SvStatus {
    ffi_entry("sv_handle_attest_verify", || {
        if wire_ptr.is_null()
            || out_side_pk_32.is_null()
            || out_handle.is_null()
            || out_issued_at.is_null()
        {
            set_last_error("sv_handle_attest_verify: null pointer argument");
            return SvStatus::NullPtr;
        }
        // SAFETY: caller contract — wire_ptr is readable for wire_len bytes.
        let wire = unsafe { std::slice::from_raw_parts(wire_ptr, wire_len) };
        let (status, payload) = status_from(HandleAttestPayload::from_wire_bytes(wire));
        let payload = match payload {
            Some(p) => p,
            None => return status,
        };

        // Allocate the handle string up-front so the function is atomic on
        // success/failure (mirrors the contact.rs precedent).
        let handle_ptr = string_to_ffi(payload.handle);
        if handle_ptr.is_null() {
            set_last_error("sv_handle_attest_verify: handle contained interior NUL");
            return SvStatus::Decode;
        }

        // SAFETY: caller contract — all output pointers are writable; side
        // pubkey is 32 bytes; string pointer is valid until freed.
        unsafe {
            std::ptr::copy_nonoverlapping(payload.side.as_ptr(), out_side_pk_32, PUBLIC_KEY_LEN);
            std::ptr::write(out_handle, handle_ptr);
            std::ptr::write(out_issued_at, payload.issued_at);
        }
        SvStatus::Ok
    })
}

/// Verify a `PagePublishPayload` wire encoding and extract the side public
/// key, slug, MIME type, content bytes, and published-at timestamp.
///
/// Inputs:
///   * `wire_ptr`, `wire_len` — the CBOR-encoded PagePublish bytes.
///
/// Outputs (all required):
///   * `out_side_pk_32` — writable 32-byte buffer for the publishing side.
///   * `*out_slug` — heap-allocated NUL-terminated C string with the slug.
///     Free with [`sv_free_string`](crate::sv_free_string).
///   * `*out_mime` — heap-allocated NUL-terminated C string with the MIME.
///     Free with [`sv_free_string`](crate::sv_free_string).
///   * `*out_content_ptr` / `*out_content_len` — heap-allocated content
///     bytes. Free with [`sv_free_buffer`](crate::sv_free_buffer).
///   * `out_published_at` — writable u64.
///
/// On error, no outputs are modified and any partially allocated buffers
/// are freed before returning.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sv_page_publish_verify(
    wire_ptr: *const u8,
    wire_len: usize,
    out_side_pk_32: *mut u8,
    out_slug: *mut *mut c_char,
    out_mime: *mut *mut c_char,
    out_content_ptr: *mut *mut u8,
    out_content_len: *mut usize,
    out_published_at: *mut u64,
) -> SvStatus {
    ffi_entry("sv_page_publish_verify", || {
        if wire_ptr.is_null()
            || out_side_pk_32.is_null()
            || out_slug.is_null()
            || out_mime.is_null()
            || out_content_ptr.is_null()
            || out_content_len.is_null()
            || out_published_at.is_null()
        {
            set_last_error("sv_page_publish_verify: null pointer argument");
            return SvStatus::NullPtr;
        }
        // SAFETY: caller contract — wire_ptr is readable for wire_len bytes.
        let wire = unsafe { std::slice::from_raw_parts(wire_ptr, wire_len) };
        let (status, payload) = status_from(PagePublishPayload::from_wire_bytes(wire));
        let payload = match payload {
            Some(p) => p,
            None => return status,
        };

        // Allocate all three output buffers up-front. If any fails, free
        // the ones that succeeded so the caller sees an atomic failure.
        let slug_ptr = string_to_ffi(payload.slug);
        if slug_ptr.is_null() {
            set_last_error("sv_page_publish_verify: slug contained interior NUL");
            return SvStatus::Decode;
        }
        let mime_ptr = string_to_ffi(payload.mime);
        if mime_ptr.is_null() {
            // SAFETY: slug_ptr came from CString::into_raw via string_to_ffi.
            unsafe {
                drop(std::ffi::CString::from_raw(slug_ptr));
            }
            set_last_error("sv_page_publish_verify: mime contained interior NUL");
            return SvStatus::Decode;
        }
        let (content_ptr, content_len) = vec_to_ffi(payload.content);

        // SAFETY: caller contract — all output pointers are writable; side
        // pubkey is 32 bytes; buffer pointers are valid until freed.
        unsafe {
            std::ptr::copy_nonoverlapping(payload.side.as_ptr(), out_side_pk_32, PUBLIC_KEY_LEN);
            std::ptr::write(out_slug, slug_ptr);
            std::ptr::write(out_mime, mime_ptr);
            std::ptr::write(out_content_ptr, content_ptr);
            std::ptr::write(out_content_len, content_len);
            std::ptr::write(out_published_at, payload.published_at);
        }
        clear_last_error();
        SvStatus::Ok
    })
}

/// Verify a 64-byte Ed25519 signature against a 32-byte public key and an
/// arbitrary message. Returns `SvStatus::Ok` if the signature verifies,
/// `SvStatus::Crypto` if it doesn't, `SvStatus::Decode` if the public key
/// is not a valid Ed25519 point.
///
/// This is the thin wrapper used by the Laravel paired-device sign-in flow
/// to verify a side's signature over an auth challenge. The challenge
/// message itself is constructed PHP-side; this function only checks the
/// math.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sv_verify_signature(
    pubkey_32: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_64: *const u8,
) -> SvStatus {
    ffi_entry("sv_verify_signature", || {
        if pubkey_32.is_null() || sig_64.is_null() {
            set_last_error("sv_verify_signature: null pointer argument");
            return SvStatus::NullPtr;
        }
        // msg_ptr may be null only if msg_len == 0 (empty message is legal).
        if msg_ptr.is_null() && msg_len != 0 {
            set_last_error("sv_verify_signature: null message pointer with non-zero length");
            return SvStatus::NullPtr;
        }

        // SAFETY: caller contract — pubkey_32 is a 32-byte readable buffer.
        let pk_slice = unsafe { std::slice::from_raw_parts(pubkey_32, PUBLIC_KEY_LEN) };
        let mut pk_arr = [0u8; PUBLIC_KEY_LEN];
        pk_arr.copy_from_slice(pk_slice);
        let pk = match PublicKey::from_bytes(&pk_arr) {
            Ok(p) => p,
            Err(e) => {
                set_last_error(format!("sv_verify_signature: {e}"));
                return SvStatus::Decode;
            }
        };

        // SAFETY: caller contract — sig_64 is a 64-byte readable buffer.
        let sig_slice = unsafe { std::slice::from_raw_parts(sig_64, SIGNATURE_LEN) };
        let mut sig_arr = [0u8; SIGNATURE_LEN];
        sig_arr.copy_from_slice(sig_slice);

        // msg_ptr may be null when msg_len is 0; from_raw_parts requires a
        // non-null dangling pointer even with zero length, so synthesize one.
        let msg = if msg_len == 0 {
            &[][..]
        } else {
            // SAFETY: caller contract — msg_ptr is readable for msg_len bytes.
            unsafe { std::slice::from_raw_parts(msg_ptr, msg_len) }
        };

        match pk.verify(msg, &sig_arr) {
            Ok(()) => {
                clear_last_error();
                SvStatus::Ok
            }
            Err(e) => {
                set_last_error(format!("sv_verify_signature: {e}"));
                SvStatus::Crypto
            }
        }
    })
}

/// Compute a 32-byte BLAKE3 hash of an arbitrary message. Used by the
/// Laravel registry as a content-address for HTTP ETag caching — the
/// same hash function the protocol uses for canonical signing, so a
/// page's BLAKE3 is stable across re-encodings.
///
/// Inputs:
///   * `msg_ptr` / `msg_len` — the bytes to hash.
///
/// Output:
///   * `out_hash_32` — writable 32-byte buffer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sv_blake3(
    msg_ptr: *const u8,
    msg_len: usize,
    out_hash_32: *mut u8,
) -> SvStatus {
    ffi_entry("sv_blake3", || {
        if out_hash_32.is_null() {
            set_last_error("sv_blake3: null output buffer");
            return SvStatus::NullPtr;
        }
        if msg_ptr.is_null() && msg_len != 0 {
            set_last_error("sv_blake3: null message pointer with non-zero length");
            return SvStatus::NullPtr;
        }
        let msg = if msg_len == 0 {
            &[][..]
        } else {
            // SAFETY: caller contract — msg_ptr is readable for msg_len bytes.
            unsafe { std::slice::from_raw_parts(msg_ptr, msg_len) }
        };
        let digest = blake3::hash(msg);
        // SAFETY: caller contract — out_hash_32 is writable for 32 bytes.
        unsafe {
            std::ptr::copy_nonoverlapping(digest.as_bytes().as_ptr(), out_hash_32, 32);
        }
        clear_last_error();
        SvStatus::Ok
    })
}

/// Compose a `DirectoryEntryPayload` for a single handle from its parts.
///
/// The registry stores claimed handles with their already-signed
/// `HandleAttest` wire bytes; this function takes that wire (plus the
/// side pubkey and handle for redundant validation) and produces the
/// canonical CBOR encoding the registry serves at
/// `/.well-known/sidevers/resolve/{handle}`.
///
/// Inputs:
///   * `side_pk_32` — the 32-byte side public key that owns the handle.
///   * `handle` — NUL-terminated UTF-8 handle string.
///   * `attestation_wire_ptr` / `attestation_wire_len` — the signed
///     `HandleAttestPayload` bytes (will be verified before composition).
///
/// Outputs:
///   * `*out_wire_ptr` / `*out_wire_len` — heap-allocated CBOR bytes;
///     free with [`sv_free_buffer`](crate::sv_free_buffer).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sv_directory_entry_encode(
    side_pk_32: *const u8,
    handle: *const c_char,
    attestation_wire_ptr: *const u8,
    attestation_wire_len: usize,
    out_wire_ptr: *mut *mut u8,
    out_wire_len: *mut usize,
) -> SvStatus {
    ffi_entry("sv_directory_entry_encode", || {
        if side_pk_32.is_null()
            || handle.is_null()
            || attestation_wire_ptr.is_null()
            || out_wire_ptr.is_null()
            || out_wire_len.is_null()
        {
            set_last_error("sv_directory_entry_encode: null pointer argument");
            return SvStatus::NullPtr;
        }
        // SAFETY: caller contract — side_pk_32 is a 32-byte readable buffer.
        let pk_slice = unsafe { std::slice::from_raw_parts(side_pk_32, PUBLIC_KEY_LEN) };
        let mut side = [0u8; PUBLIC_KEY_LEN];
        side.copy_from_slice(pk_slice);

        // SAFETY: caller contract — handle is a NUL-terminated UTF-8 C string.
        let handle_bytes = match unsafe { cstr_with_cap(handle) } {
            Some(b) => b,
            None => {
                set_last_error(
                    "sv_directory_entry_encode: handle not NUL-terminated within length cap",
                );
                return SvStatus::InvalidInput;
            }
        };
        let handle_str = match std::str::from_utf8(handle_bytes) {
            Ok(s) => s.to_owned(),
            Err(_) => {
                set_last_error("sv_directory_entry_encode: handle is not valid UTF-8");
                return SvStatus::InvalidInput;
            }
        };

        // SAFETY: caller contract — attestation_wire_ptr is readable for
        // attestation_wire_len bytes.
        let attest_wire =
            unsafe { std::slice::from_raw_parts(attestation_wire_ptr, attestation_wire_len) };
        let (status, attest) = status_from(HandleAttestPayload::from_wire_bytes(attest_wire));
        let attest = match attest {
            Some(a) => a,
            None => return status,
        };

        // Sanity-check the parts match what the caller claimed — defends
        // against the caller accidentally pairing a handle with the wrong
        // attestation row.
        if attest.side != side || attest.handle != handle_str {
            set_last_error(
                "sv_directory_entry_encode: attestation does not match (side, handle) args",
            );
            return SvStatus::InvalidInput;
        }

        let payload = DirectoryEntryPayload {
            side,
            handle: handle_str,
            attestations: vec![attest],
        };
        let bytes = payload.encode();
        let (ptr, len) = vec_to_ffi(bytes);
        // SAFETY: caller contract — both out pointers are writable.
        unsafe {
            std::ptr::write(out_wire_ptr, ptr);
            std::ptr::write(out_wire_len, len);
        }
        clear_last_error();
        SvStatus::Ok
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use sidevers_core::keys::{MasterKey, SideKey};

    fn fresh_side(label: &str) -> SideKey {
        let seed = [0x42u8; 32];
        let master = MasterKey::from_seed(&seed);
        master.derive_side(&label.into()).unwrap()
    }

    #[test]
    fn handle_attest_verify_round_trips() {
        let side = fresh_side("test");
        let payload = HandleAttestPayload::sign(&side, "omar", 1_700_000_000).unwrap();
        let wire = payload.to_wire_bytes();

        let mut out_pk = [0u8; PUBLIC_KEY_LEN];
        let mut out_handle: *mut c_char = std::ptr::null_mut();
        let mut out_issued_at: u64 = 0;
        let status = unsafe {
            sv_handle_attest_verify(
                wire.as_ptr(),
                wire.len(),
                out_pk.as_mut_ptr(),
                &mut out_handle,
                &mut out_issued_at,
            )
        };
        assert_eq!(status, SvStatus::Ok);
        assert_eq!(out_pk, side.public_bytes());
        assert_eq!(out_issued_at, 1_700_000_000);
        let handle = unsafe { std::ffi::CStr::from_ptr(out_handle) }
            .to_str()
            .unwrap();
        assert_eq!(handle, "omar");
        unsafe {
            drop(std::ffi::CString::from_raw(out_handle));
        }
    }

    #[test]
    fn handle_attest_verify_rejects_tampered_wire() {
        let side = fresh_side("test");
        let payload = HandleAttestPayload::sign(&side, "omar", 1_700_000_000).unwrap();
        let mut wire = payload.to_wire_bytes();
        let last = wire.len() - 1;
        wire[last] ^= 0x01;

        let mut out_pk = [0u8; PUBLIC_KEY_LEN];
        let mut out_handle: *mut c_char = std::ptr::null_mut();
        let mut out_issued_at: u64 = 0;
        let status = unsafe {
            sv_handle_attest_verify(
                wire.as_ptr(),
                wire.len(),
                out_pk.as_mut_ptr(),
                &mut out_handle,
                &mut out_issued_at,
            )
        };
        assert_ne!(status, SvStatus::Ok);
        assert!(out_handle.is_null());
    }

    #[test]
    fn page_publish_verify_round_trips() {
        let side = fresh_side("test");
        let payload = PagePublishPayload::sign(
            &side,
            "hello",
            "text/markdown",
            b"# Hello\n".to_vec(),
            1_700_000_000,
        )
        .unwrap();
        let wire = payload.to_wire_bytes();

        let mut out_pk = [0u8; PUBLIC_KEY_LEN];
        let mut out_slug: *mut c_char = std::ptr::null_mut();
        let mut out_mime: *mut c_char = std::ptr::null_mut();
        let mut out_content: *mut u8 = std::ptr::null_mut();
        let mut out_content_len: usize = 0;
        let mut out_pub_at: u64 = 0;
        let status = unsafe {
            sv_page_publish_verify(
                wire.as_ptr(),
                wire.len(),
                out_pk.as_mut_ptr(),
                &mut out_slug,
                &mut out_mime,
                &mut out_content,
                &mut out_content_len,
                &mut out_pub_at,
            )
        };
        assert_eq!(status, SvStatus::Ok);
        assert_eq!(out_pk, side.public_bytes());
        assert_eq!(out_pub_at, 1_700_000_000);
        let slug = unsafe { std::ffi::CStr::from_ptr(out_slug) }
            .to_str()
            .unwrap();
        let mime = unsafe { std::ffi::CStr::from_ptr(out_mime) }
            .to_str()
            .unwrap();
        let content =
            unsafe { std::slice::from_raw_parts(out_content, out_content_len) }.to_vec();
        assert_eq!(slug, "hello");
        assert_eq!(mime, "text/markdown");
        assert_eq!(content, b"# Hello\n");
        unsafe {
            drop(std::ffi::CString::from_raw(out_slug));
            drop(std::ffi::CString::from_raw(out_mime));
            let _ = Box::from_raw(std::ptr::slice_from_raw_parts_mut(
                out_content,
                out_content_len,
            ));
        }
    }

    #[test]
    fn verify_signature_round_trips() {
        let side = fresh_side("test");
        let pk = side.public_bytes();
        let msg = b"sidevers/v1/web-auth/test-nonce";
        let sig = side.sign(msg);

        let status = unsafe {
            sv_verify_signature(pk.as_ptr(), msg.as_ptr(), msg.len(), sig.as_ptr())
        };
        assert_eq!(status, SvStatus::Ok);
    }

    #[test]
    fn verify_signature_rejects_wrong_message() {
        let side = fresh_side("test");
        let pk = side.public_bytes();
        let msg = b"signed-this";
        let other = b"not-this";
        let sig = side.sign(msg);

        let status = unsafe {
            sv_verify_signature(pk.as_ptr(), other.as_ptr(), other.len(), sig.as_ptr())
        };
        assert_eq!(status, SvStatus::Crypto);
    }

    #[test]
    fn verify_signature_accepts_empty_message() {
        let side = fresh_side("test");
        let pk = side.public_bytes();
        let sig = side.sign(b"");
        let status = unsafe { sv_verify_signature(pk.as_ptr(), std::ptr::null(), 0, sig.as_ptr()) };
        assert_eq!(status, SvStatus::Ok);
    }

    #[test]
    fn directory_entry_encode_round_trips_via_core_decoder() {
        use std::ffi::CString;
        use sidevers_core::DirectoryEntryPayload;

        let side = fresh_side("test");
        let attest = HandleAttestPayload::sign(&side, "omar", 1_700_000_000).unwrap();
        let attest_wire = attest.to_wire_bytes();
        let pk = side.public_bytes();
        let handle = CString::new("omar").unwrap();

        let mut out_wire: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let status = unsafe {
            sv_directory_entry_encode(
                pk.as_ptr(),
                handle.as_ptr(),
                attest_wire.as_ptr(),
                attest_wire.len(),
                &mut out_wire,
                &mut out_len,
            )
        };
        assert_eq!(status, SvStatus::Ok);
        let bytes = unsafe { std::slice::from_raw_parts(out_wire, out_len) }.to_vec();

        let entry = DirectoryEntryPayload::decode(&bytes).unwrap();
        assert_eq!(entry.side, pk);
        assert_eq!(entry.handle, "omar");
        assert_eq!(entry.attestations.len(), 1);

        unsafe {
            let _ = Box::from_raw(std::ptr::slice_from_raw_parts_mut(out_wire, out_len));
        }
    }

    #[test]
    fn blake3_matches_reference_for_known_input() {
        let msg = b"abc";
        let mut out = [0u8; 32];
        let status = unsafe { sv_blake3(msg.as_ptr(), msg.len(), out.as_mut_ptr()) };
        assert_eq!(status, SvStatus::Ok);
        // BLAKE3 of "abc" — canonical reference vector.
        let expected =
            hex::decode("6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85")
                .unwrap();
        assert_eq!(&out[..], &expected[..]);
    }

    #[test]
    fn blake3_handles_empty_message() {
        let mut out = [0u8; 32];
        let status = unsafe { sv_blake3(std::ptr::null(), 0, out.as_mut_ptr()) };
        assert_eq!(status, SvStatus::Ok);
        let expected =
            hex::decode("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262")
                .unwrap();
        assert_eq!(&out[..], &expected[..]);
    }

    #[test]
    fn directory_entry_encode_rejects_mismatched_handle() {
        use std::ffi::CString;

        let side = fresh_side("test");
        let attest = HandleAttestPayload::sign(&side, "omar", 1_700_000_000).unwrap();
        let attest_wire = attest.to_wire_bytes();
        let pk = side.public_bytes();
        let handle = CString::new("not-omar").unwrap();

        let mut out_wire: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let status = unsafe {
            sv_directory_entry_encode(
                pk.as_ptr(),
                handle.as_ptr(),
                attest_wire.as_ptr(),
                attest_wire.len(),
                &mut out_wire,
                &mut out_len,
            )
        };
        assert_eq!(status, SvStatus::InvalidInput);
        assert!(out_wire.is_null());
    }
}
