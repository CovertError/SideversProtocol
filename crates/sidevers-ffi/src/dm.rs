//! Direct-message FFI: seal a text DM, open one received over the wire.
//!
//! This is the "mobile lite mode" entry point per Launch §3.6: signing and
//! decryption happen on-device; networking goes through a paired desktop or
//! hosted node via system QUIC (not exposed here).

use sidevers_core::keys::{PUBLIC_KEY_LEN, SECRET_KEY_LEN, SideKey};
use sidevers_core::messages::direct::{DirectBody, DirectKind, DirectMessagePayload};
use sidevers_core::payload as core_payload;
use sidevers_core::{Envelope, MessageType};
use zeroize::Zeroize;

use crate::error::{SvStatus, ffi_entry, set_last_error, status_from};
use crate::mem::vec_to_ffi;

/// Build a signed, encrypted DirectMessage envelope ready for the wire.
///
/// Inputs:
///   * `sender_seed_32` — sender's side seed (32 bytes).
///   * `recipient_pubkey_32` — recipient's side public key (32 bytes).
///   * `text_utf8`, `text_len` — the message body. Must be valid UTF-8.
///
/// On success, `*out_wire_ptr` is set to a heap-allocated buffer of length
/// `*out_wire_len`. Free with [`sv_free_buffer`](crate::sv_free_buffer).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sv_dm_seal_text(
    sender_seed_32: *const u8,
    recipient_pubkey_32: *const u8,
    text_utf8: *const u8,
    text_len: usize,
    out_wire_ptr: *mut *mut u8,
    out_wire_len: *mut usize,
) -> SvStatus {
    ffi_entry("sv_dm_seal_text", || {
        if sender_seed_32.is_null()
            || recipient_pubkey_32.is_null()
            || text_utf8.is_null()
            || out_wire_ptr.is_null()
            || out_wire_len.is_null()
        {
            set_last_error("sv_dm_seal_text: null pointer argument");
            return SvStatus::NullPtr;
        }

        // SAFETY: caller contract.
        let seed = unsafe { std::slice::from_raw_parts(sender_seed_32, SECRET_KEY_LEN) };
        let mut seed_arr = [0u8; SECRET_KEY_LEN];
        seed_arr.copy_from_slice(seed);
        let side = SideKey::from_seed(&seed_arr, "(ffi-dm-send)");
        // Wipe the stack copy now that `side` owns its own zeroizing buffer
        // (Audit P1.A).
        seed_arr.zeroize();

        // SAFETY: caller contract.
        let recipient_pk =
            unsafe { std::slice::from_raw_parts(recipient_pubkey_32, PUBLIC_KEY_LEN) };
        let mut recipient_arr = [0u8; PUBLIC_KEY_LEN];
        recipient_arr.copy_from_slice(recipient_pk);

        // SAFETY: caller contract; we just borrow `text_len` bytes.
        let text_bytes = unsafe { std::slice::from_raw_parts(text_utf8, text_len) };
        let text = match std::str::from_utf8(text_bytes) {
            Ok(s) => s.to_owned(),
            Err(_) => {
                set_last_error("sv_dm_seal_text: text is not valid UTF-8");
                return SvStatus::InvalidInput;
            }
        };

        let inner_payload = DirectMessagePayload {
            kind: DirectKind::Text,
            body: DirectBody::Text(text),
            reply_to: None,
            thread: None,
        }
        .encode();

        let result = (|| -> sidevers_core::Result<Vec<u8>> {
            let nonce = sidevers_core::envelope::random_nonce()?;
            let ts = sidevers_core::envelope::now_unix_seconds()?;
            let ciphertext =
                core_payload::seal(&inner_payload, &side, &recipient_arr, &nonce, b"")?;
            let env = Envelope::sign_with(
                MessageType::DIRECT_MESSAGE,
                &side,
                Some(recipient_arr),
                ciphertext,
                ts,
                nonce,
            )?;
            Ok(env.to_wire_bytes())
        })();

        let (status, wire) = status_from(result);
        if let Some(bytes) = wire {
            let (ptr, len) = vec_to_ffi(bytes);
            // SAFETY: caller contract — out_wire_ptr/out_wire_len are valid writes.
            unsafe {
                std::ptr::write(out_wire_ptr, ptr);
                std::ptr::write(out_wire_len, len);
            }
        }
        status
    })
}

/// Verify, decrypt, and extract the plaintext body of a DirectMessage
/// envelope addressed to this side.
///
/// Inputs:
///   * `recipient_seed_32` — this side's seed (32 bytes).
///   * `wire_ptr`, `wire_len` — the envelope bytes received over the wire.
///
/// Outputs:
///   * `*out_text_ptr` / `*out_text_len` — the decoded plaintext (heap-
///     allocated; free with [`sv_free_buffer`](crate::sv_free_buffer)).
///   * `out_sender_pubkey_32` — the sender's side public key (the envelope's
///     `from` field). MUST point to a writable 32-byte buffer.
///
/// Returns `SvStatus::Crypto` if the signature or decryption fails;
/// `SvStatus::InvalidInput` if the envelope isn't a text DirectMessage
/// addressed to this side.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sv_dm_open_text(
    recipient_seed_32: *const u8,
    wire_ptr: *const u8,
    wire_len: usize,
    out_sender_pubkey_32: *mut u8,
    out_text_ptr: *mut *mut u8,
    out_text_len: *mut usize,
) -> SvStatus {
    ffi_entry("sv_dm_open_text", || {
        if recipient_seed_32.is_null()
            || wire_ptr.is_null()
            || out_sender_pubkey_32.is_null()
            || out_text_ptr.is_null()
            || out_text_len.is_null()
        {
            set_last_error("sv_dm_open_text: null pointer argument");
            return SvStatus::NullPtr;
        }

        // SAFETY: caller contract.
        let seed = unsafe { std::slice::from_raw_parts(recipient_seed_32, SECRET_KEY_LEN) };
        let mut seed_arr = [0u8; SECRET_KEY_LEN];
        seed_arr.copy_from_slice(seed);
        let recipient_side = SideKey::from_seed(&seed_arr, "(ffi-dm-recv)");
        // Audit P1.A — wipe the stack copy of the seed.
        seed_arr.zeroize();
        let recipient_pk = recipient_side.public_bytes();

        // SAFETY: caller contract.
        let wire = unsafe { std::slice::from_raw_parts(wire_ptr, wire_len) };

        let env = match Envelope::from_wire_bytes(wire) {
            Ok(e) => e,
            Err(e) => {
                let (status, _) = status_from::<()>(Err(e));
                return status;
            }
        };

        if env.message_type != MessageType::DIRECT_MESSAGE {
            set_last_error("sv_dm_open_text: envelope is not a DirectMessage");
            return SvStatus::InvalidInput;
        }
        match env.to {
            Some(to) if to == recipient_pk => {}
            _ => {
                set_last_error("sv_dm_open_text: envelope is not addressed to this side");
                return SvStatus::InvalidInput;
            }
        }

        let plain =
            match core_payload::open(&env.payload, &recipient_side, &env.from, &env.nonce, b"") {
                Ok(p) => p,
                Err(e) => {
                    let (status, _) = status_from::<()>(Err(e));
                    return status;
                }
            };

        let payload = match DirectMessagePayload::decode(&plain) {
            Ok(p) => p,
            Err(e) => {
                let (status, _) = status_from::<()>(Err(e));
                return status;
            }
        };
        let text = match payload.body {
            DirectBody::Text(s) => s.into_bytes(),
            DirectBody::ReferenceBytes(_) => {
                set_last_error("sv_dm_open_text: media DMs not supported in FFI yet");
                return SvStatus::InvalidInput;
            }
        };

        // SAFETY: caller contract — out_sender_pubkey_32 is writable 32 bytes.
        unsafe {
            std::ptr::copy_nonoverlapping(env.from.as_ptr(), out_sender_pubkey_32, PUBLIC_KEY_LEN);
        }
        let (ptr, len) = vec_to_ffi(text);
        // SAFETY: caller contract — out_text_ptr/out_text_len are valid writes.
        unsafe {
            std::ptr::write(out_text_ptr, ptr);
            std::ptr::write(out_text_len, len);
        }
        crate::error::clear_last_error();
        SvStatus::Ok
    })
}
