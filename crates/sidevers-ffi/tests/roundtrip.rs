//! Integration tests for the Sidevers FFI surface.
//!
//! Each test drives the `extern "C"` functions exactly as a foreign-language
//! binding (Swift / Kotlin / C) would: with raw pointers, manual memory
//! management, and status-code checking. If a test fails here, the same
//! call from a real mobile client would fail.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::ffi::{CStr, CString};

use sidevers::*;

fn cstr(s: &str) -> CString {
    CString::new(s).unwrap()
}

#[test]
fn keygen_master_fills_seed() {
    let mut seed = [0u8; 32];
    let status = unsafe { sv_keygen_master(seed.as_mut_ptr()) };
    assert_eq!(status, SvStatus::Ok);
    // Astronomically unlikely the CSPRNG returns all-zeros.
    assert!(seed.iter().any(|&b| b != 0));
}

#[test]
fn keygen_master_rejects_null_out() {
    let status = unsafe { sv_keygen_master(std::ptr::null_mut()) };
    assert_eq!(status, SvStatus::NullPtr);
}

#[test]
fn derive_side_then_pubkey_matches_address() {
    let mut master = [0u8; 32];
    unsafe { sv_keygen_master(master.as_mut_ptr()) };

    let mut side_seed = [0u8; 32];
    let label = cstr("work");
    let status = unsafe { sv_derive_side(master.as_ptr(), label.as_ptr(), side_seed.as_mut_ptr()) };
    assert_eq!(status, SvStatus::Ok);

    let mut pubkey = [0u8; 32];
    let status = unsafe { sv_pubkey_from_seed(side_seed.as_ptr(), pubkey.as_mut_ptr()) };
    assert_eq!(status, SvStatus::Ok);

    // Encode -> decode round trip.
    let addr_ptr = unsafe { sv_address_encode(pubkey.as_ptr(), SvAddressKind::Side) };
    assert!(!addr_ptr.is_null());
    let addr_str = unsafe { CStr::from_ptr(addr_ptr) }
        .to_str()
        .unwrap()
        .to_owned();
    assert!(addr_str.starts_with("sv1"));

    let mut decoded_pk = [0u8; 32];
    let mut decoded_kind = SvAddressKind::Side;
    let status = unsafe {
        sv_address_decode(
            addr_ptr,
            decoded_pk.as_mut_ptr(),
            &mut decoded_kind as *mut SvAddressKind,
        )
    };
    assert_eq!(status, SvStatus::Ok);
    assert_eq!(decoded_pk, pubkey);
    assert_eq!(decoded_kind, SvAddressKind::Side);

    unsafe { sv_free_string(addr_ptr) };
}

#[test]
fn address_decode_rejects_mixed_case() {
    let bogus = cstr("sv1ABCdef");
    let mut pk = [0u8; 32];
    let mut kind = SvAddressKind::Side;
    let status = unsafe { sv_address_decode(bogus.as_ptr(), pk.as_mut_ptr(), &mut kind) };
    assert_ne!(status, SvStatus::Ok);
}

#[test]
fn dm_seal_then_open_round_trips() {
    // Set up two parties.
    let mut alice_master = [0u8; 32];
    let mut bob_master = [0u8; 32];
    unsafe {
        sv_keygen_master(alice_master.as_mut_ptr());
        sv_keygen_master(bob_master.as_mut_ptr());
    }
    let mut alice_side = [0u8; 32];
    let mut bob_side = [0u8; 32];
    let work = cstr("work");
    let close = cstr("close");
    unsafe {
        sv_derive_side(
            alice_master.as_ptr(),
            work.as_ptr(),
            alice_side.as_mut_ptr(),
        );
        sv_derive_side(bob_master.as_ptr(), close.as_ptr(), bob_side.as_mut_ptr());
    }
    let mut bob_pk = [0u8; 32];
    unsafe { sv_pubkey_from_seed(bob_side.as_ptr(), bob_pk.as_mut_ptr()) };

    // Alice seals a DM to Bob.
    let text = b"hello from the FFI";
    let mut wire_ptr: *mut u8 = std::ptr::null_mut();
    let mut wire_len: usize = 0;
    let status = unsafe {
        sv_dm_seal_text(
            alice_side.as_ptr(),
            bob_pk.as_ptr(),
            text.as_ptr(),
            text.len(),
            &mut wire_ptr,
            &mut wire_len,
        )
    };
    assert_eq!(status, SvStatus::Ok);
    assert!(!wire_ptr.is_null());
    assert!(wire_len > text.len()); // envelope is bigger than payload

    // Bob opens the DM.
    let mut alice_pk_seen = [0u8; 32];
    let mut text_ptr: *mut u8 = std::ptr::null_mut();
    let mut text_len: usize = 0;
    let status = unsafe {
        sv_dm_open_text(
            bob_side.as_ptr(),
            wire_ptr,
            wire_len,
            alice_pk_seen.as_mut_ptr(),
            &mut text_ptr,
            &mut text_len,
        )
    };
    assert_eq!(status, SvStatus::Ok);
    assert_eq!(text_len, text.len());
    let received = unsafe { std::slice::from_raw_parts(text_ptr, text_len) };
    assert_eq!(received, text);

    // Sender pubkey matches Alice's.
    let mut alice_pk_expected = [0u8; 32];
    unsafe { sv_pubkey_from_seed(alice_side.as_ptr(), alice_pk_expected.as_mut_ptr()) };
    assert_eq!(alice_pk_seen, alice_pk_expected);

    unsafe {
        sv_free_buffer(wire_ptr, wire_len);
        sv_free_buffer(text_ptr, text_len);
    }
}

#[test]
fn dm_open_with_wrong_recipient_returns_crypto_error() {
    let mut alice_master = [0u8; 32];
    let mut bob_master = [0u8; 32];
    let mut eve_master = [0u8; 32];
    unsafe {
        sv_keygen_master(alice_master.as_mut_ptr());
        sv_keygen_master(bob_master.as_mut_ptr());
        sv_keygen_master(eve_master.as_mut_ptr());
    }
    let mut alice_side = [0u8; 32];
    let mut bob_side = [0u8; 32];
    let mut eve_side = [0u8; 32];
    let label = cstr("close");
    unsafe {
        sv_derive_side(
            alice_master.as_ptr(),
            label.as_ptr(),
            alice_side.as_mut_ptr(),
        );
        sv_derive_side(bob_master.as_ptr(), label.as_ptr(), bob_side.as_mut_ptr());
        sv_derive_side(eve_master.as_ptr(), label.as_ptr(), eve_side.as_mut_ptr());
    }
    let mut bob_pk = [0u8; 32];
    unsafe { sv_pubkey_from_seed(bob_side.as_ptr(), bob_pk.as_mut_ptr()) };

    let mut wire_ptr: *mut u8 = std::ptr::null_mut();
    let mut wire_len: usize = 0;
    unsafe {
        sv_dm_seal_text(
            alice_side.as_ptr(),
            bob_pk.as_ptr(),
            b"x".as_ptr(),
            1,
            &mut wire_ptr,
            &mut wire_len,
        );
    }

    // Eve tries to open. Should fail (envelope is addressed to bob; eve isn't the recipient).
    let mut sender = [0u8; 32];
    let mut text_ptr: *mut u8 = std::ptr::null_mut();
    let mut text_len = 0usize;
    let status = unsafe {
        sv_dm_open_text(
            eve_side.as_ptr(),
            wire_ptr,
            wire_len,
            sender.as_mut_ptr(),
            &mut text_ptr,
            &mut text_len,
        )
    };
    assert_ne!(status, SvStatus::Ok);

    unsafe { sv_free_buffer(wire_ptr, wire_len) };
}

#[test]
fn linkage_sign_and_verify_round_trip() {
    // Two sides of the same user (alice's master, two labels).
    let mut master = [0u8; 32];
    unsafe { sv_keygen_master(master.as_mut_ptr()) };
    let mut side_a = [0u8; 32];
    let mut side_b = [0u8; 32];
    let lbl_a = cstr("public");
    let lbl_b = cstr("private");
    unsafe {
        sv_derive_side(master.as_ptr(), lbl_a.as_ptr(), side_a.as_mut_ptr());
        sv_derive_side(master.as_ptr(), lbl_b.as_ptr(), side_b.as_mut_ptr());
    }

    let mut wire_ptr: *mut u8 = std::ptr::null_mut();
    let mut wire_len = 0usize;
    let status = unsafe {
        sv_linkage_sign(
            side_a.as_ptr(),
            side_b.as_ptr(),
            1_700_000_000,
            &mut wire_ptr,
            &mut wire_len,
        )
    };
    assert_eq!(status, SvStatus::Ok);

    let mut out_a = [0u8; 32];
    let mut out_b = [0u8; 32];
    let mut out_ts = 0u64;
    let status = unsafe {
        sv_linkage_verify(
            wire_ptr,
            wire_len,
            out_a.as_mut_ptr(),
            out_b.as_mut_ptr(),
            &mut out_ts,
        )
    };
    assert_eq!(status, SvStatus::Ok);
    assert_eq!(out_ts, 1_700_000_000);

    // out_a / out_b should be the side public keys.
    let mut pk_a = [0u8; 32];
    let mut pk_b = [0u8; 32];
    unsafe {
        sv_pubkey_from_seed(side_a.as_ptr(), pk_a.as_mut_ptr());
        sv_pubkey_from_seed(side_b.as_ptr(), pk_b.as_mut_ptr());
    }
    assert_eq!(out_a, pk_a);
    assert_eq!(out_b, pk_b);

    unsafe { sv_free_buffer(wire_ptr, wire_len) };
}

#[test]
fn linkage_verify_tampered_fails() {
    let mut master = [0u8; 32];
    unsafe { sv_keygen_master(master.as_mut_ptr()) };
    let mut side_a = [0u8; 32];
    let mut side_b = [0u8; 32];
    let lbl_a = cstr("a");
    let lbl_b = cstr("b");
    unsafe {
        sv_derive_side(master.as_ptr(), lbl_a.as_ptr(), side_a.as_mut_ptr());
        sv_derive_side(master.as_ptr(), lbl_b.as_ptr(), side_b.as_mut_ptr());
    }
    let mut wire_ptr: *mut u8 = std::ptr::null_mut();
    let mut wire_len = 0usize;
    unsafe {
        sv_linkage_sign(
            side_a.as_ptr(),
            side_b.as_ptr(),
            1,
            &mut wire_ptr,
            &mut wire_len,
        );
    }
    // Tamper.
    unsafe {
        let byte_ptr = wire_ptr.add(wire_len - 1);
        std::ptr::write(byte_ptr, std::ptr::read(byte_ptr) ^ 0x01);
    }
    let mut out_a = [0u8; 32];
    let mut out_b = [0u8; 32];
    let mut out_ts = 0u64;
    let status = unsafe {
        sv_linkage_verify(
            wire_ptr,
            wire_len,
            out_a.as_mut_ptr(),
            out_b.as_mut_ptr(),
            &mut out_ts,
        )
    };
    assert_ne!(status, SvStatus::Ok);
    unsafe { sv_free_buffer(wire_ptr, wire_len) };
}

#[test]
fn contact_card_encode_then_parse_round_trips_through_real_ffi() {
    // Alice mints her side, packs it into a contact card, hands the URI to
    // Bob's client out-of-band, Bob parses it and now knows where to dial.
    // This is the bootstrap-from-zero path: no Sidevers server involved.
    let mut alice_master = [0u8; 32];
    unsafe { sv_keygen_master(alice_master.as_mut_ptr()) };
    let mut alice_side_seed = [0u8; 32];
    let label = cstr("public");
    unsafe {
        sv_derive_side(
            alice_master.as_ptr(),
            label.as_ptr(),
            alice_side_seed.as_mut_ptr(),
        )
    };
    let mut alice_pk = [0u8; 32];
    unsafe { sv_pubkey_from_seed(alice_side_seed.as_ptr(), alice_pk.as_mut_ptr()) };

    let dial = cstr("203.0.113.42:4242");
    let name = cstr("Alice");
    let role = cstr("public");
    let mut uri_ptr: *mut std::os::raw::c_char = std::ptr::null_mut();
    let status = unsafe {
        sv_contact_card_encode(
            alice_pk.as_ptr(),
            dial.as_ptr(),
            name.as_ptr(),
            role.as_ptr(),
            &mut uri_ptr,
        )
    };
    assert_eq!(status, SvStatus::Ok);
    assert!(!uri_ptr.is_null());
    let uri = unsafe { CStr::from_ptr(uri_ptr) }.to_str().unwrap();
    assert!(uri.starts_with("sidevers-contact:1:"));

    let mut out_side = [0u8; 32];
    let mut out_dial: *mut std::os::raw::c_char = std::ptr::null_mut();
    let mut out_name: *mut std::os::raw::c_char = std::ptr::null_mut();
    let mut out_label: *mut std::os::raw::c_char = std::ptr::null_mut();
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
    assert_eq!(out_side, alice_pk);
    assert_eq!(
        unsafe { CStr::from_ptr(out_dial) }.to_str().unwrap(),
        "203.0.113.42:4242"
    );
    assert_eq!(
        unsafe { CStr::from_ptr(out_name) }.to_str().unwrap(),
        "Alice"
    );
    assert_eq!(
        unsafe { CStr::from_ptr(out_label) }.to_str().unwrap(),
        "public"
    );

    unsafe {
        sv_free_string(uri_ptr);
        sv_free_string(out_dial);
        sv_free_string(out_name);
        sv_free_string(out_label);
    }
}

#[test]
fn contact_card_minimal_fields_parses_with_null_optionals() {
    let side = [0xAAu8; 32];
    let dial = cstr("[2001:db8::1]:4242");
    let mut uri_ptr: *mut std::os::raw::c_char = std::ptr::null_mut();
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

    let mut out_side = [0u8; 32];
    let mut out_dial: *mut std::os::raw::c_char = std::ptr::null_mut();
    let mut out_name: *mut std::os::raw::c_char = std::ptr::null_mut();
    let mut out_label: *mut std::os::raw::c_char = std::ptr::null_mut();
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
    assert!(out_name.is_null());
    assert!(out_label.is_null());

    unsafe {
        sv_free_string(uri_ptr);
        sv_free_string(out_dial);
    }
}

#[test]
fn contact_card_parse_rejects_non_sidevers_uri() {
    let bogus = cstr("https://example.com");
    let mut side = [0u8; 32];
    let mut a: *mut std::os::raw::c_char = std::ptr::null_mut();
    let mut b: *mut std::os::raw::c_char = std::ptr::null_mut();
    let mut c: *mut std::os::raw::c_char = std::ptr::null_mut();
    let status =
        unsafe { sv_contact_card_parse(bogus.as_ptr(), side.as_mut_ptr(), &mut a, &mut b, &mut c) };
    assert_ne!(status, SvStatus::Ok);
    assert!(a.is_null());
    assert!(b.is_null());
    assert!(c.is_null());
}

#[test]
fn last_error_message_round_trip() {
    // Trigger an error.
    let bogus = cstr("sv1ABCdef");
    let mut pk = [0u8; 32];
    let mut kind = SvAddressKind::Side;
    let status = unsafe { sv_address_decode(bogus.as_ptr(), pk.as_mut_ptr(), &mut kind) };
    assert_ne!(status, SvStatus::Ok);

    let err_ptr = sv_last_error_message();
    assert!(!err_ptr.is_null());
    let err_str = unsafe { CStr::from_ptr(err_ptr) }.to_str().unwrap();
    assert!(!err_str.is_empty());
    unsafe { sv_free_string(err_ptr) };
}
