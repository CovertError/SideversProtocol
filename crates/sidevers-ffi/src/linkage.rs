//! Linkage-proof FFI: sign a proof that two sides belong to the same person,
//! and verify one received from outside.

use sidevers_core::keys::{PUBLIC_KEY_LEN, SECRET_KEY_LEN, SideKey};
use sidevers_core::linkage::LinkageProof;
use zeroize::Zeroize;

use crate::error::{SvStatus, ffi_entry, set_last_error, status_from};
use crate::mem::vec_to_ffi;

/// Sign a fresh linkage proof binding `side_a` and `side_b` (both belonging
/// to the caller). On success returns the wire bytes — a CBOR record both
/// sides have signed, verifiable by anyone holding it.
///
/// Inputs:
///   * `side_a_seed_32`, `side_b_seed_32` — the two side seeds (32 bytes each).
///   * `issued_at` — unix seconds timestamp.
///
/// Outputs:
///   * `*out_wire_ptr` / `*out_wire_len` — heap-allocated wire bytes; free
///     with [`sv_free_buffer`](crate::sv_free_buffer).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sv_linkage_sign(
    side_a_seed_32: *const u8,
    side_b_seed_32: *const u8,
    issued_at: u64,
    out_wire_ptr: *mut *mut u8,
    out_wire_len: *mut usize,
) -> SvStatus {
    ffi_entry("sv_linkage_sign", || {
        if side_a_seed_32.is_null()
            || side_b_seed_32.is_null()
            || out_wire_ptr.is_null()
            || out_wire_len.is_null()
        {
            set_last_error("sv_linkage_sign: null pointer argument");
            return SvStatus::NullPtr;
        }
        // SAFETY: caller contract.
        let a = unsafe { std::slice::from_raw_parts(side_a_seed_32, SECRET_KEY_LEN) };
        let b = unsafe { std::slice::from_raw_parts(side_b_seed_32, SECRET_KEY_LEN) };
        let mut a_arr = [0u8; SECRET_KEY_LEN];
        let mut b_arr = [0u8; SECRET_KEY_LEN];
        a_arr.copy_from_slice(a);
        b_arr.copy_from_slice(b);
        let side_a = SideKey::from_seed(&a_arr, "(ffi-linkage-a)");
        let side_b = SideKey::from_seed(&b_arr, "(ffi-linkage-b)");
        // Audit P1.A — wipe the stack copies of both seeds.
        a_arr.zeroize();
        b_arr.zeroize();

        let result = LinkageProof::sign(&side_a, &side_b, issued_at).map(|p| p.to_wire_bytes());
        let (status, wire) = status_from(result);
        if let Some(bytes) = wire {
            let (ptr, len) = vec_to_ffi(bytes);
            // SAFETY: caller contract.
            unsafe {
                std::ptr::write(out_wire_ptr, ptr);
                std::ptr::write(out_wire_len, len);
            }
        }
        status
    })
}

/// Verify a linkage-proof wire encoding and extract the two side public
/// keys and the issued-at timestamp.
///
/// Inputs:
///   * `wire_ptr`, `wire_len` — the proof bytes.
///
/// Outputs:
///   * `out_side_a_32`, `out_side_b_32` — writable 32-byte buffers.
///   * `out_issued_at` — writable u64.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sv_linkage_verify(
    wire_ptr: *const u8,
    wire_len: usize,
    out_side_a_32: *mut u8,
    out_side_b_32: *mut u8,
    out_issued_at: *mut u64,
) -> SvStatus {
    ffi_entry("sv_linkage_verify", || {
        if wire_ptr.is_null()
            || out_side_a_32.is_null()
            || out_side_b_32.is_null()
            || out_issued_at.is_null()
        {
            set_last_error("sv_linkage_verify: null pointer argument");
            return SvStatus::NullPtr;
        }
        // SAFETY: caller contract.
        let wire = unsafe { std::slice::from_raw_parts(wire_ptr, wire_len) };
        let (status, proof) = status_from(LinkageProof::from_wire_bytes(wire));
        if let Some(p) = proof {
            // SAFETY: caller contract.
            unsafe {
                std::ptr::copy_nonoverlapping(p.side_a.as_ptr(), out_side_a_32, PUBLIC_KEY_LEN);
                std::ptr::copy_nonoverlapping(p.side_b.as_ptr(), out_side_b_32, PUBLIC_KEY_LEN);
                std::ptr::write(out_issued_at, p.issued_at);
            }
        }
        status
    })
}
