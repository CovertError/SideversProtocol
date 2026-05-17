//! Bech32m address codec across the FFI.

use std::os::raw::c_char;

use sidevers_core::{Address, AddressKind};

use crate::error::{SvStatus, ffi_entry, set_last_error, status_from};
use crate::mem::{cstr_with_cap, string_to_ffi};

/// Address kind tag for [`sv_address_encode`] / [`sv_address_decode`].
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SvAddressKind {
    /// A side (sv1q…) — a person, or any addressable identity.
    Side = 0,
    /// A verse (svv1q…) — a shared space.
    Verse = 1,
}

impl SvAddressKind {
    fn to_core(self) -> AddressKind {
        match self {
            SvAddressKind::Side => AddressKind::Side,
            SvAddressKind::Verse => AddressKind::Verse,
        }
    }
    fn from_core(k: AddressKind) -> Self {
        match k {
            AddressKind::Side => SvAddressKind::Side,
            AddressKind::Verse => SvAddressKind::Verse,
        }
    }
}

/// Encode a 32-byte Ed25519 public key as a bech32m Sidevers address.
///
/// `pubkey_32` MUST point to a 32-byte buffer. Returns a heap-allocated
/// NUL-terminated C string (`sv1q…` for sides, `svv1q…` for verses); free
/// with [`sv_free_string`](crate::sv_free_string). Returns null on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sv_address_encode(
    pubkey_32: *const u8,
    kind: SvAddressKind,
) -> *mut c_char {
    // Audit P1.B — wrap the FFI boundary in catch_unwind. Returns null on
    // panic so the C caller sees the failure instead of a UB unwind.
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if pubkey_32.is_null() {
            set_last_error("sv_address_encode: pubkey_32 is null");
            return std::ptr::null_mut();
        }
        // SAFETY: caller contract.
        let pk = unsafe { std::slice::from_raw_parts(pubkey_32, 32) };
        let mut arr = [0u8; 32];
        arr.copy_from_slice(pk);
        let addr = Address::new(kind.to_core(), arr);
        string_to_ffi(addr.encode())
    })) {
        Ok(p) => p,
        Err(_) => {
            set_last_error("sv_address_encode: panicked at FFI boundary");
            std::ptr::null_mut()
        }
    }
}

/// Parse a bech32m address into its 32-byte public key + kind.
///
/// `addr` MUST be a NUL-terminated UTF-8 C string. `out_pubkey_32` MUST
/// point to a writable 32-byte buffer. `out_kind` MUST point to a writable
/// `SvAddressKind`. On error, both outputs are left untouched.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sv_address_decode(
    addr: *const c_char,
    out_pubkey_32: *mut u8,
    out_kind: *mut SvAddressKind,
) -> SvStatus {
    ffi_entry("sv_address_decode", || {
        if addr.is_null() || out_pubkey_32.is_null() || out_kind.is_null() {
            set_last_error("sv_address_decode: null pointer argument");
            return SvStatus::NullPtr;
        }
        // SAFETY: caller contract. Length-capped scan (Audit P2.E).
        let addr_bytes = match unsafe { cstr_with_cap(addr) } {
            Some(b) => b,
            None => {
                set_last_error("sv_address_decode: address not NUL-terminated within length cap");
                return SvStatus::InvalidInput;
            }
        };
        let s = match std::str::from_utf8(addr_bytes) {
            Ok(s) => s,
            Err(_) => {
                set_last_error("sv_address_decode: address is not valid UTF-8");
                return SvStatus::InvalidInput;
            }
        };
        let (status, parsed) = status_from(Address::parse(s));
        if let Some(p) = parsed {
            let bytes = p.key_bytes();
            // SAFETY: caller contract.
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_pubkey_32, 32);
                std::ptr::write(out_kind, SvAddressKind::from_core(p.kind()));
            }
        }
        status
    })
}
