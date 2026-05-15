//! Sidevers desktop — Tauri 2 shell exposing a small set of
//! `sidevers-core` operations to a vanilla HTML/JS frontend.
//!
//! Operations covered:
//!   * generate_master         — fresh 32-byte master seed
//!   * derive_side             — derive a side seed from a master + label
//!   * pubkey_from_seed        — Ed25519 pubkey for any 32-byte seed
//!   * encode_address          — bech32m-encode a pubkey as side/verse
//!   * seal_dm / open_dm       — sign + encrypt / verify + decrypt a DM
//!
//! Networking (running a node, gossip fanout, storage I/O) lives in the
//! `sidevers-node` daemon and is intentionally outside this scaffold.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use sidevers_core::keys::{MasterKey, SECRET_KEY_LEN, SideKey};
use sidevers_core::messages::direct::{DirectBody, DirectKind, DirectMessagePayload};
use sidevers_core::payload as core_payload;
use sidevers_core::{Address, AddressKind, Envelope, MessageType};

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

fn seed_from_hex(s: &str) -> Result<[u8; SECRET_KEY_LEN], String> {
    let v = hex::decode(s.trim()).map_err(|e| e.to_string())?;
    if v.len() != SECRET_KEY_LEN {
        return Err(format!(
            "expected {SECRET_KEY_LEN}-byte seed, got {}",
            v.len()
        ));
    }
    let mut arr = [0u8; SECRET_KEY_LEN];
    arr.copy_from_slice(&v);
    Ok(arr)
}

fn pubkey_from_hex(s: &str) -> Result<[u8; 32], String> {
    let v = hex::decode(s.trim()).map_err(|e| e.to_string())?;
    if v.len() != 32 {
        return Err(format!("expected 32-byte pubkey, got {}", v.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&v);
    Ok(arr)
}

// ---------------------------------------------------------------------
// Tauri commands
// ---------------------------------------------------------------------

#[tauri::command]
fn generate_master() -> Result<String, String> {
    let m = MasterKey::generate().map_err(|e| e.to_string())?;
    Ok(hex::encode(m.to_seed()))
}

#[tauri::command]
fn derive_side(master_hex: String, label: String) -> Result<String, String> {
    let seed = seed_from_hex(&master_hex)?;
    let master = MasterKey::from_seed(&seed);
    let side = master
        .derive_side(&label.into())
        .map_err(|e| e.to_string())?;
    Ok(hex::encode(side.to_seed()))
}

#[tauri::command]
fn pubkey_from_seed(seed_hex: String) -> Result<String, String> {
    let seed = seed_from_hex(&seed_hex)?;
    let side = SideKey::from_seed(&seed, "(desktop)");
    Ok(hex::encode(side.public_bytes()))
}

#[tauri::command]
fn encode_address(pubkey_hex: String, kind: String) -> Result<String, String> {
    let pubkey = pubkey_from_hex(&pubkey_hex)?;
    let k = match kind.as_str() {
        "side" => AddressKind::Side,
        "verse" => AddressKind::Verse,
        other => return Err(format!("unknown address kind {other:?}")),
    };
    Ok(Address::new(k, pubkey).encode())
}

#[tauri::command]
fn seal_dm(
    sender_seed_hex: String,
    recipient_pubkey_hex: String,
    text: String,
) -> Result<String, String> {
    let sender_seed = seed_from_hex(&sender_seed_hex)?;
    let sender = SideKey::from_seed(&sender_seed, "(desktop-dm-send)");
    let recipient = pubkey_from_hex(&recipient_pubkey_hex)?;

    let inner = DirectMessagePayload {
        kind: DirectKind::Text,
        body: DirectBody::Text(text),
        reply_to: None,
        thread: None,
    }
    .encode();

    let nonce = sidevers_core::envelope::random_nonce().map_err(|e| e.to_string())?;
    let ts = sidevers_core::envelope::now_unix_seconds().map_err(|e| e.to_string())?;
    let ciphertext =
        core_payload::seal(&inner, &sender, &recipient, &nonce, b"").map_err(|e| e.to_string())?;
    let env = Envelope::sign_with(
        MessageType::DIRECT_MESSAGE,
        &sender,
        Some(recipient),
        ciphertext,
        ts,
        nonce,
    )
    .map_err(|e| e.to_string())?;
    Ok(hex::encode(env.to_wire_bytes()))
}

#[tauri::command]
fn open_dm(recipient_seed_hex: String, wire_hex: String) -> Result<String, String> {
    let seed = seed_from_hex(&recipient_seed_hex)?;
    let side = SideKey::from_seed(&seed, "(desktop-dm-recv)");
    let recipient_pk = side.public_bytes();
    let wire = hex::decode(wire_hex.trim()).map_err(|e| e.to_string())?;

    let env = Envelope::from_wire_bytes(&wire).map_err(|e| e.to_string())?;
    if env.message_type != MessageType::DIRECT_MESSAGE {
        return Err("envelope is not a DirectMessage".into());
    }
    if env.to.as_ref() != Some(&recipient_pk) {
        return Err("envelope is not addressed to this side".into());
    }
    let plain = core_payload::open(&env.payload, &side, &env.from, &env.nonce, b"")
        .map_err(|e| e.to_string())?;
    let dm = DirectMessagePayload::decode(&plain).map_err(|e| e.to_string())?;
    match dm.body {
        DirectBody::Text(s) => Ok(s),
        DirectBody::ReferenceBytes(_) => Err("media DMs not yet supported in the desktop UI".into()),
    }
}

// ---------------------------------------------------------------------
// Entrypoint
// ---------------------------------------------------------------------

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            generate_master,
            derive_side,
            pubkey_from_seed,
            encode_address,
            seal_dm,
            open_dm,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
