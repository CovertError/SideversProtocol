//! Sidevers JNI bridge.
//!
//! Exposes a small set of Sidevers operations under the JNI naming
//! convention so Kotlin's `external fun` declarations bind directly. Every
//! function:
//!
//!   * Takes `JNIEnv` + `JClass` + Kotlin-facing arguments (jbyteArray,
//!     JString, etc.).
//!   * Translates Kotlin types into Rust types via the `jni` crate's
//!     safe wrappers.
//!   * Calls into `sidevers_core` for the actual protocol work.
//!   * Translates Rust outputs back into JNI types, OR throws a Java
//!     `RuntimeException` with the error message on failure.
//!
//! Loaded by Kotlin via `System.loadLibrary("sidevers_jni")`.

use jni::JNIEnv;
use jni::objects::{JByteArray, JClass, JString};
use jni::sys::jbyteArray;

use sidevers_core::keys::{MasterKey, SECRET_KEY_LEN, SideKey};
use sidevers_core::linkage::LinkageProof;
use sidevers_core::messages::direct::{DirectBody, DirectKind, DirectMessagePayload};
use sidevers_core::payload as core_payload;
use sidevers_core::{Address, AddressKind, Envelope, MessageType};

// =========================================================================
// Helpers
// =========================================================================

fn throw_error(env: &mut JNIEnv, msg: &str) {
    // Ignore the result — if throwing fails, we have bigger problems.
    let _ = env.throw_new("java/lang/RuntimeException", msg);
}

fn jbytes_to_vec(env: &mut JNIEnv, arr: &JByteArray) -> Result<Vec<u8>, String> {
    env.convert_byte_array(arr).map_err(|e| e.to_string())
}

fn vec_to_jbytes(env: &JNIEnv, bytes: &[u8]) -> Result<jbyteArray, String> {
    let arr = env.byte_array_from_slice(bytes).map_err(|e| e.to_string())?;
    Ok(arr.into_raw())
}

fn jstring_to_string(env: &mut JNIEnv, js: &JString) -> Result<String, String> {
    let raw: String = env.get_string(js).map_err(|e| e.to_string())?.into();
    Ok(raw)
}

fn seed_from_bytes(v: Vec<u8>) -> Result<[u8; SECRET_KEY_LEN], String> {
    if v.len() != SECRET_KEY_LEN {
        return Err(format!("expected {SECRET_KEY_LEN}-byte seed, got {}", v.len()));
    }
    let mut arr = [0u8; SECRET_KEY_LEN];
    arr.copy_from_slice(&v);
    Ok(arr)
}

// =========================================================================
// JNI exports
// =========================================================================

/// Generate a fresh master seed. Returns a 32-byte `ByteArray` on success;
/// throws `RuntimeException` on CSPRNG failure.
///
/// Kotlin: `external fun nativeKeygenMaster(): ByteArray`
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_sidevers_SideversCore_nativeKeygenMaster<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jbyteArray {
    match MasterKey::generate() {
        Ok(master) => {
            let seed = master.to_seed();
            vec_to_jbytes(&env, &seed).unwrap_or_else(|e| {
                throw_error(&mut env, &e);
                std::ptr::null_mut()
            })
        }
        Err(e) => {
            throw_error(&mut env, &e.to_string());
            std::ptr::null_mut()
        }
    }
}

/// Derive a side seed from a master seed under the given UTF-8 label.
///
/// Kotlin: `external fun nativeDeriveSide(masterSeed: ByteArray, label: String): ByteArray`
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_sidevers_SideversCore_nativeDeriveSide<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    master_seed: JByteArray<'local>,
    label: JString<'local>,
) -> jbyteArray {
    let result = || -> Result<jbyteArray, String> {
        let seed_v = jbytes_to_vec(&mut env, &master_seed)?;
        let seed = seed_from_bytes(seed_v)?;
        let label_s = jstring_to_string(&mut env, &label)?;
        let master = MasterKey::from_seed(&seed);
        let side = master
            .derive_side(&label_s.into())
            .map_err(|e| e.to_string())?;
        vec_to_jbytes(&env, &side.to_seed())
    }();
    match result {
        Ok(arr) => arr,
        Err(e) => {
            throw_error(&mut env, &e);
            std::ptr::null_mut()
        }
    }
}

/// Compute the 32-byte Ed25519 public key for any seed.
///
/// Kotlin: `external fun nativePubkeyFromSeed(seed: ByteArray): ByteArray`
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_sidevers_SideversCore_nativePubkeyFromSeed<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    seed: JByteArray<'local>,
) -> jbyteArray {
    let result = || -> Result<jbyteArray, String> {
        let v = jbytes_to_vec(&mut env, &seed)?;
        let arr = seed_from_bytes(v)?;
        let side = SideKey::from_seed(&arr, "(jni)");
        vec_to_jbytes(&env, &side.public_bytes())
    }();
    match result {
        Ok(arr) => arr,
        Err(e) => {
            throw_error(&mut env, &e);
            std::ptr::null_mut()
        }
    }
}

/// Bech32m-encode an Ed25519 public key. `kind`: 0 = side, 1 = verse.
///
/// Kotlin: `external fun nativeAddressEncode(pubkey: ByteArray, kind: Byte): String`
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_sidevers_SideversCore_nativeAddressEncode<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    pubkey: JByteArray<'local>,
    kind: jni::sys::jbyte,
) -> jni::sys::jstring {
    let result = || -> Result<String, String> {
        let v = jbytes_to_vec(&mut env, &pubkey)?;
        if v.len() != 32 {
            return Err(format!("pubkey must be 32 bytes, got {}", v.len()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&v);
        let addr_kind = match kind {
            0 => AddressKind::Side,
            1 => AddressKind::Verse,
            _ => return Err(format!("unknown address kind {kind}")),
        };
        Ok(Address::new(addr_kind, arr).encode())
    }();
    match result {
        Ok(s) => match env.new_string(&s) {
            Ok(js) => js.into_raw(),
            Err(e) => {
                throw_error(&mut env, &e.to_string());
                std::ptr::null_mut()
            }
        },
        Err(e) => {
            throw_error(&mut env, &e);
            std::ptr::null_mut()
        }
    }
}

/// Build a signed, encrypted DirectMessage envelope.
///
/// Kotlin: `external fun nativeSealDirectMessage(senderSeed: ByteArray, recipientPubkey: ByteArray, text: String): ByteArray`
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_sidevers_SideversCore_nativeSealDirectMessage<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    sender_seed: JByteArray<'local>,
    recipient_pubkey: JByteArray<'local>,
    text: JString<'local>,
) -> jbyteArray {
    let result = || -> Result<jbyteArray, String> {
        let s_v = jbytes_to_vec(&mut env, &sender_seed)?;
        let s = seed_from_bytes(s_v)?;
        let side = SideKey::from_seed(&s, "(jni-dm-send)");
        let r_v = jbytes_to_vec(&mut env, &recipient_pubkey)?;
        if r_v.len() != 32 {
            return Err(format!("recipient pubkey must be 32 bytes, got {}", r_v.len()));
        }
        let mut r = [0u8; 32];
        r.copy_from_slice(&r_v);
        let text_s = jstring_to_string(&mut env, &text)?;

        let inner = DirectMessagePayload {
            kind: DirectKind::Text,
            body: DirectBody::Text(text_s),
            reply_to: None,
            thread: None,
        }
        .encode();

        let nonce = sidevers_core::envelope::random_nonce().map_err(|e| e.to_string())?;
        let ts = sidevers_core::envelope::now_unix_seconds().map_err(|e| e.to_string())?;
        let ciphertext =
            core_payload::seal(&inner, &side, &r, &nonce, b"").map_err(|e| e.to_string())?;
        let env_msg = Envelope::sign_with(
            MessageType::DIRECT_MESSAGE,
            &side,
            Some(r),
            ciphertext,
            ts,
            nonce,
        )
        .map_err(|e| e.to_string())?;
        vec_to_jbytes(&env, &env_msg.to_wire_bytes())
    }();
    match result {
        Ok(arr) => arr,
        Err(e) => {
            throw_error(&mut env, &e);
            std::ptr::null_mut()
        }
    }
}

/// Verify + decrypt a DM envelope. Returns the plaintext text as a String;
/// throws on any failure.
///
/// Kotlin: `external fun nativeOpenDirectMessageText(recipientSeed: ByteArray, wire: ByteArray): String`
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_sidevers_SideversCore_nativeOpenDirectMessageText<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    recipient_seed: JByteArray<'local>,
    wire: JByteArray<'local>,
) -> jni::sys::jstring {
    let result = || -> Result<String, String> {
        let r_v = jbytes_to_vec(&mut env, &recipient_seed)?;
        let r = seed_from_bytes(r_v)?;
        let side = SideKey::from_seed(&r, "(jni-dm-recv)");
        let recipient_pk = side.public_bytes();
        let wire_v = jbytes_to_vec(&mut env, &wire)?;

        let env_msg = Envelope::from_wire_bytes(&wire_v).map_err(|e| e.to_string())?;
        if env_msg.message_type != MessageType::DIRECT_MESSAGE {
            return Err("envelope is not a DirectMessage".into());
        }
        if env_msg.to.as_ref() != Some(&recipient_pk) {
            return Err("envelope is not addressed to this side".into());
        }
        let plain = core_payload::open(
            &env_msg.payload,
            &side,
            &env_msg.from,
            &env_msg.nonce,
            b"",
        )
        .map_err(|e| e.to_string())?;
        let dm = DirectMessagePayload::decode(&plain).map_err(|e| e.to_string())?;
        match dm.body {
            DirectBody::Text(s) => Ok(s),
            DirectBody::ReferenceBytes(_) => Err("media DMs not supported in JNI yet".into()),
        }
    }();
    match result {
        Ok(s) => match env.new_string(&s) {
            Ok(js) => js.into_raw(),
            Err(e) => {
                throw_error(&mut env, &e.to_string());
                std::ptr::null_mut()
            }
        },
        Err(e) => {
            throw_error(&mut env, &e);
            std::ptr::null_mut()
        }
    }
}

/// Sign a fresh linkage proof.
///
/// Kotlin: `external fun nativeSignLinkage(sideA: ByteArray, sideB: ByteArray, issuedAt: Long): ByteArray`
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_sidevers_SideversCore_nativeSignLinkage<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    side_a: JByteArray<'local>,
    side_b: JByteArray<'local>,
    issued_at: jni::sys::jlong,
) -> jbyteArray {
    let result = || -> Result<jbyteArray, String> {
        let a = seed_from_bytes(jbytes_to_vec(&mut env, &side_a)?)?;
        let b = seed_from_bytes(jbytes_to_vec(&mut env, &side_b)?)?;
        let ka = SideKey::from_seed(&a, "(jni-linkage-a)");
        let kb = SideKey::from_seed(&b, "(jni-linkage-b)");
        let proof = LinkageProof::sign(&ka, &kb, issued_at as u64).map_err(|e| e.to_string())?;
        vec_to_jbytes(&env, &proof.to_wire_bytes())
    }();
    match result {
        Ok(arr) => arr,
        Err(e) => {
            throw_error(&mut env, &e);
            std::ptr::null_mut()
        }
    }
}
