//! Key-generation FFI: master seed, side derivation, public-key extraction.

use std::ffi::CStr;
use std::os::raw::c_char;

use sidevers_core::keys::{MasterKey, SECRET_KEY_LEN, SideKey};

use crate::error::{SvStatus, set_last_error, status_from};

/// Generate a fresh master seed from the OS CSPRNG.
///
/// `out_seed_32` MUST point to a writable 32-byte buffer. On success the
/// buffer is filled with the master seed (the user's identity root — keep
/// this private).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sv_keygen_master(out_seed_32: *mut u8) -> SvStatus {
    if out_seed_32.is_null() {
        set_last_error("sv_keygen_master: out_seed_32 is null");
        return SvStatus::NullPtr;
    }
    let result = std::panic::catch_unwind(MasterKey::generate);
    match result {
        Ok(Ok(master)) => {
            let seed = master.to_seed();
            // SAFETY: caller promised `out_seed_32` is at least 32 bytes.
            unsafe {
                std::ptr::copy_nonoverlapping(seed.as_ptr(), out_seed_32, SECRET_KEY_LEN);
            }
            SvStatus::Ok
        }
        Ok(Err(e)) => status_from::<()>(Err(e)).0,
        Err(_) => {
            set_last_error("sv_keygen_master: internal panic");
            SvStatus::Internal
        }
    }
}

/// Derive a side keypair from a master seed under the given UTF-8 label.
///
/// `master_seed_32` MUST point to a 32-byte buffer. `label` MUST be a
/// NUL-terminated UTF-8 string. `out_side_seed_32` MUST point to a writable
/// 32-byte buffer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sv_derive_side(
    master_seed_32: *const u8,
    label: *const c_char,
    out_side_seed_32: *mut u8,
) -> SvStatus {
    if master_seed_32.is_null() || label.is_null() || out_side_seed_32.is_null() {
        set_last_error("sv_derive_side: null pointer argument");
        return SvStatus::NullPtr;
    }
    // SAFETY: caller contract — master_seed_32 is a valid 32-byte read.
    let seed = unsafe { std::slice::from_raw_parts(master_seed_32, SECRET_KEY_LEN) };
    let mut seed_arr = [0u8; SECRET_KEY_LEN];
    seed_arr.copy_from_slice(seed);

    // SAFETY: caller contract — label is a valid NUL-terminated C string.
    let label_str = match unsafe { CStr::from_ptr(label) }.to_str() {
        Ok(s) => s.to_owned(),
        Err(_) => {
            set_last_error("sv_derive_side: label is not valid UTF-8");
            return SvStatus::InvalidInput;
        }
    };

    let master = MasterKey::from_seed(&seed_arr);
    let result = master.derive_side(&label_str.into());
    let (status, side) = status_from(result);
    if let Some(side) = side {
        let side_seed = side.to_seed();
        // SAFETY: caller promised `out_side_seed_32` is at least 32 bytes.
        unsafe {
            std::ptr::copy_nonoverlapping(side_seed.as_ptr(), out_side_seed_32, SECRET_KEY_LEN);
        }
    }
    status
}

/// Compute the public key for an Ed25519 seed (works for master, side, or
/// verse keypairs — they all share the same key space).
///
/// `seed_32` MUST point to a 32-byte buffer. `out_pubkey_32` MUST point to
/// a writable 32-byte buffer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sv_pubkey_from_seed(
    seed_32: *const u8,
    out_pubkey_32: *mut u8,
) -> SvStatus {
    if seed_32.is_null() || out_pubkey_32.is_null() {
        set_last_error("sv_pubkey_from_seed: null pointer argument");
        return SvStatus::NullPtr;
    }
    // SAFETY: caller contract.
    let seed = unsafe { std::slice::from_raw_parts(seed_32, SECRET_KEY_LEN) };
    let mut seed_arr = [0u8; SECRET_KEY_LEN];
    seed_arr.copy_from_slice(seed);
    let side = SideKey::from_seed(&seed_arr, "(ffi)");
    let pk = side.public_bytes();
    // SAFETY: caller contract.
    unsafe {
        std::ptr::copy_nonoverlapping(pk.as_ptr(), out_pubkey_32, 32);
    }
    SvStatus::Ok
}
