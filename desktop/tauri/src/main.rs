//! Sidevers desktop — Tauri 2 shell exposing live `sidevers-node` operations
//! to a vanilla HTML/JS frontend.
//!
//! The window owns a `tokio::sync::Mutex<Option<sidevers_net::Node>>` and a
//! `tokio::sync::Mutex<Option<Session>>` as managed state. The frontend
//! drives the node lifecycle:
//!
//!   * `start_node(data_dir, side_label)` boots an embedded node, derives a
//!     fresh master seed, derives the labeled side, opens an SQLite store,
//!     starts the QUIC listener on `127.0.0.1:0` (auto-port), and spawns a
//!     drain-loop that emits inbound DMs as Tauri events.
//!   * `connect_peer(peer_addr)` dials another node and records the
//!     `Session` so subsequent sends use it.
//!   * `send_dm(text)` sends a DM on the recorded session.
//!   * `stop_node()` shuts down and clears all state.
//!
//! Inbound DMs are emitted as `inbox:dm` Tauri events with `{from, plaintext}`.
//!
//! Networking (running a live protocol node, fanout, storage I/O) requires
//! `sidevers-net`; key-only operations (seal/open without a network) remain
//! reachable via the four legacy commands kept below as a fallback.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Serialize;
use sidevers_core::keys::{MasterKey, SECRET_KEY_LEN, SideKey};
use sidevers_core::messages::direct::{DirectBody, DirectKind, DirectMessagePayload};
use sidevers_core::payload as core_payload;
use sidevers_core::verse::{ContractObject, VerseContentKey};
use sidevers_core::{
    Address, AddressKind, ContactCard, Envelope, GroupInvite, MessageType, PairingQr,
    ProfilePayload,
};
use sidevers_net::{
    InboxEntry, InboxStore, Intent, Node, Session, SideRelationship, SideStore, VerseHost,
    VerseMembershipRecord, post_to_verse, send_dm as send_dm_helper,
};
use std::collections::BTreeSet;
use tauri::{Emitter, State};
use tokio::sync::Mutex;

/// Key used in the SideStore `settings` table to gate the onboarding
/// wizard. Set to "true" once the first-run flow completes.
const SETTING_ONBOARDING_COMPLETED: &str = "onboarding_completed";

/// Phase 3 Stage C — bech32 address of the side the user last had
/// active. The frontend writes it on every side-switch; auto_start_node
/// reads it to decide which side to put up first on relaunch.
const SETTING_LAST_ACTIVE_SIDE: &str = "last_active_side";

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
// Managed state — the embedded node + the active outbound session.
// ---------------------------------------------------------------------

#[derive(Default)]
struct AppState {
    node: Mutex<Option<Arc<Node>>>,
    /// Active outbound sessions keyed by the *encoded local side address*
    /// (e.g. "sds1…"). Each hosted side can hold its own session because
    /// each side has its own QUIC endpoint per spec §7.6.
    sessions: Mutex<HashMap<String, Session>>,
    /// Phase 3.A: SQLite-backed inbox so DMs survive an app restart.
    /// Set when a node starts; cleared on stop.
    inbox: Mutex<Option<Arc<InboxStore>>>,
}

#[derive(Serialize, Clone)]
struct NodeInfo {
    side_address: String,
    side_address_hex: String,
    listen_addr: String,
}

#[derive(Serialize, Clone)]
struct InboxDm {
    from: String,
    to: String,
    plaintext: String,
    /// Phase 3 Stage C: Unix-seconds timestamp at which this node
    /// received the DM. Lets the UI group threads by peer + sort
    /// them by recency. Stored in `inbox.received_at`; live events
    /// fill it with the current wall-clock at receive time.
    received_at: u64,
}

// ---------------------------------------------------------------------
// Phase 3.D — onboarding wizard support
// ---------------------------------------------------------------------

/// Default per-OS data dir for a fresh install. The wizard pre-fills
/// the field with this; users can override.
#[tauri::command]
fn default_data_dir() -> Result<String, String> {
    let base = directories::ProjectDirs::from("com", "sidevers", "Sidevers")
        .ok_or_else(|| "no project dir available on this platform".to_owned())?;
    Ok(base.data_dir().to_string_lossy().into_owned())
}

/// True iff the named data dir's `sides.db` already records the
/// onboarding flag. Used by the frontend on load: if false → show
/// the wizard; if true → load the main UI.
#[tauri::command]
async fn is_onboarded(data_dir: String) -> Result<bool, String> {
    let dir = PathBuf::from(&data_dir);
    if !dir.join("sides.db").exists() {
        return Ok(false);
    }
    let store = SideStore::open(&dir)
        .await
        .map_err(|e| format!("opening side store: {e}"))?;
    let v = store
        .get_setting(SETTING_ONBOARDING_COMPLETED)
        .await
        .map_err(|e| format!("read setting: {e}"))?;
    Ok(v.as_deref() == Some("true"))
}

/// Flip the onboarding flag in the data dir's settings table. Called
/// by the wizard's final step before transitioning to the main UI.
#[tauri::command]
async fn complete_onboarding(data_dir: String) -> Result<(), String> {
    let dir = PathBuf::from(&data_dir);
    tokio::fs::create_dir_all(&dir)
        .await
        .map_err(|e| format!("data_dir: {e}"))?;
    let store = SideStore::open(&dir)
        .await
        .map_err(|e| format!("opening side store: {e}"))?;
    store
        .set_setting(SETTING_ONBOARDING_COMPLETED, "true")
        .await
        .map_err(|e| format!("write setting: {e}"))?;
    Ok(())
}

// ---------------------------------------------------------------------
// Phase 3 Stage C — settings + auto-start
// ---------------------------------------------------------------------

/// Read a single setting from the side store at `data_dir`. Returns
/// `None` if the setting hasn't been written yet. Callers carry their
/// own knowledge of valid keys (e.g. `last_active_side`, `theme`,
/// `advanced_mode`); this is a thin generic wrapper.
#[tauri::command]
async fn get_setting(data_dir: String, key: String) -> Result<Option<String>, String> {
    let dir = PathBuf::from(&data_dir);
    if !dir.join("sides.db").exists() {
        return Ok(None);
    }
    let store = SideStore::open(&dir)
        .await
        .map_err(|e| format!("opening side store: {e}"))?;
    store
        .get_setting(&key)
        .await
        .map_err(|e| format!("read setting: {e}"))
}

/// Write a single setting. Creates the side store if it doesn't yet
/// exist (matches `complete_onboarding` posture).
#[tauri::command]
async fn set_setting(data_dir: String, key: String, value: String) -> Result<(), String> {
    let dir = PathBuf::from(&data_dir);
    tokio::fs::create_dir_all(&dir)
        .await
        .map_err(|e| format!("data_dir: {e}"))?;
    let store = SideStore::open(&dir)
        .await
        .map_err(|e| format!("opening side store: {e}"))?;
    store
        .set_setting(&key, &value)
        .await
        .map_err(|e| format!("write setting: {e}"))
}

/// Phase 3 Stage C — chat-first boot path.
///
/// Loads every non-retired side from `<data_dir>/sides.db`, picks the
/// "active" one (the `last_active_side` setting if set, else the
/// first non-retired side), reconstructs its `SideKey` from the
/// persisted seed, starts the node hosting it, and re-hosts every
/// other non-retired side via `add_side`. Spawns the same inbox-drain
/// task as `start_node`.
///
/// Distinct from `start_node` in one critical way: `start_node` mints
/// a *fresh* master+side every call (used by the onboarding wizard's
/// "create your first side" step). `auto_start_node` loads what's
/// already there. The frontend calls `auto_start_node` on every
/// post-onboarding launch; the wizard alone calls `start_node`.
#[tauri::command]
async fn auto_start_node(
    data_dir: String,
    state: State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<NodeInfo, String> {
    let mut guard = state.node.lock().await;
    if guard.is_some() {
        return Err("node already running — stop it first".into());
    }
    let dir = PathBuf::from(&data_dir);
    let store = SideStore::open(&dir)
        .await
        .map_err(|e| format!("opening side store: {e}"))?;
    let sides = store
        .list_sides()
        .await
        .map_err(|e| format!("list sides: {e}"))?;
    if sides.is_empty() {
        return Err("no persisted sides — run the onboarding wizard first".into());
    }

    // Pick the active side. Preference order:
    //   1. settings.last_active_side (matched by bech32 address)
    //   2. first non-retired side (BTreeMap address order)
    let last_active = store
        .get_setting(SETTING_LAST_ACTIVE_SIDE)
        .await
        .map_err(|e| format!("read last_active_side: {e}"))?;
    let active = last_active
        .as_deref()
        .and_then(|s| decode_side_address(s).ok())
        .and_then(|pk| sides.iter().find(|row| row.address == pk).cloned())
        .or_else(|| sides.iter().find(|s| !s.is_self_retired).cloned())
        .ok_or_else(|| "every persisted side is retired".to_owned())?;

    let label = active.label.as_deref().unwrap_or("(restored)");
    let side_key = SideKey::from_seed(&active.seed, label);

    let listen = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let node = Arc::new(
        Node::start(side_key, listen, &dir)
            .await
            .map_err(|e| format!("Node::start: {e}"))?,
    );
    let listen_addr = node.listen_addr();

    // Re-host every other non-retired side so the side-rail UX has
    // all the user's identities available on first paint.
    for row in &sides {
        if row.address == active.address || row.is_self_retired {
            continue;
        }
        let other_label = row.label.as_deref().unwrap_or("(restored)");
        let other_key = SideKey::from_seed(&row.seed, other_label);
        let other_listen = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        if let Err(e) = node.add_side(other_key, other_listen).await {
            // Best-effort — one bad side shouldn't block boot.
            eprintln!("auto_start_node: re-host side failed: {e}");
        }
    }

    *guard = Some(node.clone());
    drop(guard);

    // Same persistent-inbox + drain wiring as start_node.
    let inbox = Arc::new(InboxStore::open(&dir).map_err(|e| format!("inbox open: {e}"))?);
    {
        let mut ig = state.inbox.lock().await;
        *ig = Some(inbox.clone());
    }

    let node_for_drain = node.clone();
    let app_for_drain = app.clone();
    let inbox_for_drain = inbox.clone();
    tokio::spawn(async move {
        while let Some(dm) = node_for_drain.next_direct_message().await {
            let plaintext = String::from_utf8_lossy(&dm.plaintext).into_owned();
            let from = Address::new(AddressKind::Side, dm.envelope.from).encode();
            let to_addr = dm.envelope.to;
            let to = to_addr
                .map(|addr| Address::new(AddressKind::Side, addr).encode())
                .unwrap_or_default();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            if let Some(recipient) = to_addr {
                inbox_for_drain.insert(&InboxEntry {
                    to: recipient,
                    from: dm.envelope.from,
                    nonce: dm.envelope.nonce.to_vec(),
                    wire_envelope: dm.envelope.to_wire_bytes(),
                    plaintext: dm.plaintext.clone(),
                    received_at: now,
                });
            }
            let _ = app_for_drain.emit(
                "inbox:dm",
                InboxDm {
                    from,
                    to,
                    plaintext,
                    received_at: now,
                },
            );
        }
    });

    // Persist last_active_side so a subsequent restart lands on the
    // same identity even if the user didn't switch.
    let active_address = Address::new(AddressKind::Side, active.address).encode();
    let _ = store
        .set_setting(SETTING_LAST_ACTIVE_SIDE, &active_address)
        .await;

    Ok(NodeInfo {
        side_address: active_address,
        side_address_hex: hex::encode(active.address),
        listen_addr: listen_addr.to_string(),
    })
}

/// Sub-directory under `data_dir` where seed backups are written. The
/// directory is owner-only (0o700 on Unix) so files inside inherit a
/// safe default even before the per-file chmod runs.
const BACKUP_SUBDIR: &str = "backups";

/// Maximum permitted length of a backup filename (sanity bound, leaves
/// generous room for "sidevers-seed-2026-05-16.bin" style names).
const MAX_BACKUP_FILENAME_LEN: usize = 128;

/// Windows reserved device names (case-insensitive). Opening any of these
/// as a file maps to the corresponding device, silently swallowing the
/// data. Reject regardless of platform — a backup file written on macOS
/// then synced to Windows would hit the same trap.
const WIN_RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Validate a user-supplied filename for a seed backup, returning the
/// canonicalized absolute path it would land at:
/// `<canonical(data_dir)>/backups/<filename>`.
///
/// Audit P1.2 + P2.A/B/C:
/// - rejects path separators, parent-dir refs, dotfiles, NUL bytes,
///   NTFS-reserved characters;
/// - rejects Windows reserved device aliases (CON, PRN, …, LPT9) and
///   filenames ending in `.` or space;
/// - normalizes Unicode to NFC and rejects bidi-override + zero-width
///   format characters (so `"innocent\u{202E}txt.exe"` cannot pose as
///   `"innocentexe.txt"`);
/// - canonicalizes `data_dir` so a `..` segment in the data dir cannot
///   escape the intended subtree.
fn safe_backup_path(data_dir: &Path, filename: &str) -> Result<PathBuf, String> {
    use unicode_normalization::UnicodeNormalization;

    let trimmed = filename.trim();
    if trimmed.is_empty() {
        return Err("backup filename cannot be empty".into());
    }
    if trimmed.len() > MAX_BACKUP_FILENAME_LEN {
        return Err(format!(
            "backup filename too long (max {MAX_BACKUP_FILENAME_LEN} chars)"
        ));
    }
    if trimmed.contains('/') || trimmed.contains('\\') {
        return Err("backup filename must not contain path separators".into());
    }
    if trimmed == "." || trimmed == ".." || trimmed.starts_with('.') {
        return Err("backup filename cannot start with '.' or be a parent ref".into());
    }
    // NTFS-reserved characters (and NUL).
    if trimmed
        .chars()
        .any(|c| matches!(c, '\0' | ':' | '*' | '?' | '"' | '<' | '>' | '|'))
    {
        return Err("backup filename contains a forbidden character".into());
    }
    // Windows trailing `.` / space gets silently stripped by NTFS, which
    // creates confusion: the user thinks they saved `foo.` but the file
    // is at `foo`.
    if trimmed.ends_with('.') || trimmed.ends_with(' ') {
        return Err("backup filename cannot end with '.' or space".into());
    }
    // Bidi-override and zero-width / format characters can make a filename
    // display as something different from what it is on disk.
    if trimmed.chars().any(|c| {
        matches!(c,
            '\u{202A}'..='\u{202E}' |   // LRE, RLE, PDF, LRO, RLO
            '\u{2066}'..='\u{2069}' |   // LRI, RLI, FSI, PDI
            '\u{200B}'..='\u{200F}' |   // ZWSP, ZWNJ, ZWJ, LRM, RLM
            '\u{FEFF}'                  // BOM / ZWNBSP
        )
    }) {
        return Err("backup filename contains a bidi/zero-width control character".into());
    }
    // Windows reserved device names (case-insensitive, optionally with an
    // extension — `CON.bin` still aliases to the console).
    let stem: &str = trimmed.split('.').next().unwrap_or(trimmed);
    if WIN_RESERVED.iter().any(|r| stem.eq_ignore_ascii_case(r)) {
        return Err(format!(
            "backup filename uses a reserved Windows device name ({stem})"
        ));
    }
    // Normalize to NFC. Mixing NFC and NFD lets an attacker create two
    // filenames that display identically but differ on disk.
    let normalized: String = trimmed.nfc().collect();
    if normalized != trimmed {
        return Err(
            "backup filename contains non-NFC-normalized Unicode (visually ambiguous)".into(),
        );
    }
    // Canonicalize `data_dir` — if it contains `..` segments, that's
    // either a misconfiguration or an attempted bypass; either way we
    // refuse to silently follow it.
    let canonical_dir = std::fs::canonicalize(data_dir)
        .map_err(|e| format!("data_dir does not resolve to a real path: {e}"))?;
    Ok(canonical_dir.join(BACKUP_SUBDIR).join(normalized))
}

/// Write the active node's primary side seed to a passphrase-encrypted
/// backup file inside `<data_dir>/backups/<filename>`. The seed is
/// sealed with Argon2id+ChaCha20-Poly1305 (`sidevers_core::keystore`)
/// before reaching disk — even if the resulting file lands on shared
/// storage or in a backup tier, the passphrase is the only path to
/// recovery (Audit P1.1 + P1.2).
#[tauri::command]
async fn write_seed_backup(
    data_dir: String,
    filename: String,
    passphrase: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    if passphrase.is_empty() {
        return Err("a passphrase is required to back up the seed".into());
    }
    let node = {
        let g = state.node.lock().await;
        g.as_ref()
            .cloned()
            .ok_or_else(|| "node not started — backup must run after start_node".to_owned())?
    };
    let dir = PathBuf::from(&data_dir);
    let path = safe_backup_path(&dir, &filename)?;
    let backup_dir = path
        .parent()
        .ok_or_else(|| "internal: safe_backup_path returned a path with no parent".to_owned())?;
    tokio::fs::create_dir_all(backup_dir)
        .await
        .map_err(|e| format!("creating backup dir: {e}"))?;
    // Lock down the backups/ subdir to owner-only on Unix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut dir_perms = std::fs::metadata(backup_dir)
            .map_err(|e| e.to_string())?
            .permissions();
        dir_perms.set_mode(0o700);
        std::fs::set_permissions(backup_dir, dir_perms).map_err(|e| e.to_string())?;
    }

    let seed = node.side().to_seed();
    let sealed = sidevers_core::keystore::seal_seed(&seed, &passphrase)
        .map_err(|e| format!("sealing seed: {e}"))?;
    tokio::fs::write(&path, &sealed)
        .await
        .map_err(|e| format!("writing sealed seed file: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&path)
            .map_err(|e| e.to_string())?
            .permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&path, perms).map_err(|e| e.to_string())?;
    }
    // On Windows the file inherits the user's profile ACL by default
    // (data_dir is typically under %APPDATA%, which is per-user). The
    // encrypted form (Argon2id+ChaCha20-Poly1305) is the primary
    // defense; we accept the ACL gap as a documented limitation.
    Ok(path.to_string_lossy().into_owned())
}

// ---------------------------------------------------------------------
// Phase 3 Stage C polish — per-side profile photo (local-only)
// ---------------------------------------------------------------------
//
// Photos display locally only for this round; publishing on the wire
// is gated on a future `ProfilePayload` extension. The image lives at
// `<data_dir>/avatars/<bech32-no-prefix>.jpg`, chmod 0o600, in a
// 0o700 directory. The frontend resizes to 256×256 JPEG before
// sending (≈60 KB), well within Tauri's IPC budget for a base64
// blob.

const AVATAR_SUBDIR: &str = "avatars";
const AVATAR_MAX_BYTES: usize = 256 * 1024;
const JPEG_MAGIC: [u8; 3] = [0xFF, 0xD8, 0xFF];

/// `<data_dir>/avatars/<bech32-without-prefix>.jpg`. The bech32
/// stripped of its `sv1q`/`sv1p` HRP gives a filename-safe alnum
/// suffix; collisions are impossible (the pubkey is unique). Never
/// derived from user-supplied filenames — there's no path-traversal
/// surface.
fn avatar_path_for(data_dir: &Path, side_address: &str) -> Result<PathBuf, String> {
    let pk = decode_side_address(side_address)?;
    let mut name = String::with_capacity(64);
    for b in &pk {
        name.push_str(&format!("{:02x}", b));
    }
    name.push_str(".jpg");
    Ok(data_dir.join(AVATAR_SUBDIR).join(name))
}

/// Persist the active side's avatar image. Validates JPEG magic
/// bytes (frontend always produces JPEG via canvas.toBlob) before
/// writing. Refuses oversized blobs.
#[tauri::command]
async fn set_side_avatar(
    data_dir: String,
    side_address: String,
    image_b64: String,
) -> Result<(), String> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(image_b64.as_bytes())
        .map_err(|e| format!("avatar: bad base64: {e}"))?;
    if bytes.is_empty() {
        return Err("avatar: empty image".into());
    }
    if bytes.len() > AVATAR_MAX_BYTES {
        return Err(format!(
            "avatar: image too large ({} bytes; max {})",
            bytes.len(),
            AVATAR_MAX_BYTES
        ));
    }
    if bytes.len() < 3 || bytes[..3] != JPEG_MAGIC {
        return Err("avatar: only JPEG accepted (frontend should resize via canvas)".into());
    }
    let dir = PathBuf::from(&data_dir);
    let path = avatar_path_for(&dir, &side_address)?;
    let parent = path
        .parent()
        .ok_or_else(|| "internal: avatar path has no parent".to_owned())?;
    tokio::fs::create_dir_all(parent)
        .await
        .map_err(|e| format!("creating avatars dir: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(parent)
            .map_err(|e| e.to_string())?
            .permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(parent, perms).map_err(|e| e.to_string())?;
    }
    tokio::fs::write(&path, &bytes)
        .await
        .map_err(|e| format!("writing avatar: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&path)
            .map_err(|e| e.to_string())?
            .permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&path, perms).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Return the absolute path to a side's avatar file if one exists,
/// or `None`. Frontend wraps the path with Tauri's `convertFileSrc`
/// to get a webview-loadable URL.
#[tauri::command]
async fn get_side_avatar(data_dir: String, side_address: String) -> Result<Option<String>, String> {
    let dir = PathBuf::from(&data_dir);
    let path = avatar_path_for(&dir, &side_address)?;
    if tokio::fs::try_exists(&path)
        .await
        .map_err(|e| format!("stat avatar: {e}"))?
    {
        Ok(Some(path.to_string_lossy().into_owned()))
    } else {
        Ok(None)
    }
}

/// Delete the avatar file for a side. Silent no-op if it doesn't
/// exist; failure to remove a present file is an error.
#[tauri::command]
async fn clear_side_avatar(data_dir: String, side_address: String) -> Result<(), String> {
    let dir = PathBuf::from(&data_dir);
    let path = avatar_path_for(&dir, &side_address)?;
    match tokio::fs::remove_file(&path).await {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("removing avatar: {e}")),
    }
}

#[cfg(test)]
mod backup_path_tests {
    use super::{MAX_BACKUP_FILENAME_LEN, safe_backup_path};
    use std::path::PathBuf;

    /// Helper: create a real temp dir we can canonicalize against. The
    /// returned `tempfile::TempDir` cleans up on drop; the caller holds
    /// it alongside the path used in assertions.
    fn temproot() -> (tempfile::TempDir, PathBuf) {
        let td = tempfile::tempdir().expect("tempdir");
        let canon = std::fs::canonicalize(td.path()).expect("canonicalize");
        (td, canon)
    }

    #[test]
    fn good_filename_resolves_under_backups_subdir() {
        let (_td, root) = temproot();
        let p = safe_backup_path(&root, "sidevers-seed-2026-05-16.bin").unwrap();
        assert!(p.starts_with(&root.join("backups")));
        assert!(p.ends_with("sidevers-seed-2026-05-16.bin"));
    }

    #[test]
    fn rejects_forward_slash() {
        let (_td, root) = temproot();
        assert!(safe_backup_path(&root, "../etc/passwd").is_err());
        assert!(safe_backup_path(&root, "foo/bar").is_err());
    }

    #[test]
    fn rejects_backslash() {
        let (_td, root) = temproot();
        assert!(safe_backup_path(&root, "foo\\bar").is_err());
    }

    #[test]
    fn rejects_dot_and_dotdot() {
        let (_td, root) = temproot();
        assert!(safe_backup_path(&root, ".").is_err());
        assert!(safe_backup_path(&root, "..").is_err());
    }

    #[test]
    fn rejects_dotfile() {
        let (_td, root) = temproot();
        assert!(safe_backup_path(&root, ".hidden").is_err());
    }

    #[test]
    fn rejects_empty() {
        let (_td, root) = temproot();
        assert!(safe_backup_path(&root, "").is_err());
        assert!(safe_backup_path(&root, "   ").is_err());
    }

    #[test]
    fn rejects_nul_and_ntfs_reserved_chars() {
        let (_td, root) = temproot();
        assert!(safe_backup_path(&root, "a\0b").is_err());
        assert!(safe_backup_path(&root, "a:b").is_err());
        assert!(safe_backup_path(&root, "a*b").is_err());
        assert!(safe_backup_path(&root, "a?b").is_err());
        assert!(safe_backup_path(&root, "a<b>c").is_err());
        assert!(safe_backup_path(&root, "a|b").is_err());
        assert!(safe_backup_path(&root, "a\"b").is_err());
    }

    #[test]
    fn rejects_overlong_filename() {
        let (_td, root) = temproot();
        let long = "x".repeat(MAX_BACKUP_FILENAME_LEN + 1);
        assert!(safe_backup_path(&root, &long).is_err());
    }

    #[test]
    fn accepts_safe_unicode() {
        let (_td, root) = temproot();
        let p = safe_backup_path(&root, "respaldo-清醒-2026.bin").unwrap();
        assert!(p.ends_with("respaldo-清醒-2026.bin"));
    }

    // ---------- Audit P2 additions ----------

    #[test]
    fn rejects_windows_reserved_device_names_p2b() {
        let (_td, root) = temproot();
        for name in [
            "CON",
            "con",
            "PRN.bin",
            "Aux",
            "nul.txt",
            "COM1",
            "lpt9",
            "CON.SEED.bin",
        ] {
            assert!(
                safe_backup_path(&root, name).is_err(),
                "must reject Windows reserved name: {name}"
            );
        }
    }

    #[test]
    fn rejects_trailing_dot_p2b() {
        let (_td, root) = temproot();
        // Trailing `.` is silently stripped by NTFS: a file "seed.bin." on
        // disk lands as "seed.bin", confusing the user. (Trailing spaces
        // are also stripped by NTFS, but `.trim()` in safe_backup_path
        // handles that earlier — a benign UX.)
        assert!(safe_backup_path(&root, "seed.bin.").is_err());
    }

    #[test]
    fn rejects_bidi_override_filename_p2c() {
        let (_td, root) = temproot();
        // "innocent<U+202E>txt.exe" displays as "innocentexe.txt"
        let deceptive = "innocent\u{202E}txt.exe";
        assert!(safe_backup_path(&root, deceptive).is_err());
    }

    #[test]
    fn rejects_zero_width_filename_p2c() {
        let (_td, root) = temproot();
        let deceptive = "seed\u{200B}.bin"; // contains ZERO WIDTH SPACE
        assert!(safe_backup_path(&root, deceptive).is_err());
    }

    #[test]
    fn rejects_non_nfc_unicode_p2c() {
        let (_td, root) = temproot();
        // "café" composed (NFC) vs decomposed (NFD).
        // NFD form: "cafe" + combining acute (U+0301).
        let nfd = "cafe\u{0301}.bin";
        assert!(
            safe_backup_path(&root, nfd).is_err(),
            "non-NFC form must be rejected (visually ambiguous with NFC form)"
        );
        // NFC form (precomposed) is accepted.
        let nfc = "café.bin";
        assert!(safe_backup_path(&root, nfc).is_ok());
    }

    #[test]
    fn rejects_data_dir_with_dotdot_segment_p2a() {
        // Build a path that's literally `<tempdir>/../something` —
        // canonicalize() either resolves it (escaping) or errors. The
        // function must NOT silently join `<that>/backups/<file>` without
        // resolving.
        let (td, root) = temproot();
        let evil = root.join("..").join(td.path().file_name().unwrap());
        // `canonicalize` on this resolves to the same temp dir, but the
        // test is mainly that *some* canonical form is returned and we
        // didn't blindly join `..` segments.
        let p = safe_backup_path(&evil, "seed.bin").unwrap();
        // The resolved path must NOT contain ".." anywhere.
        let s = p.to_string_lossy();
        assert!(
            !s.contains("/.."),
            "canonical path must not contain `..`: {s}"
        );
    }

    #[test]
    fn errors_when_data_dir_does_not_exist_p2a() {
        // canonicalize() fails on a non-existent path.
        let nope = PathBuf::from("/this/should/really/not/exist/at/all/sv-test");
        let err = safe_backup_path(&nope, "seed.bin").unwrap_err();
        assert!(
            err.contains("data_dir does not resolve"),
            "expected data_dir resolution failure, got: {err}"
        );
    }
}

// ---------------------------------------------------------------------
// Lifecycle commands
// ---------------------------------------------------------------------

#[tauri::command]
async fn start_node(
    data_dir: String,
    side_label: String,
    state: State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<NodeInfo, String> {
    let mut guard = state.node.lock().await;
    if guard.is_some() {
        return Err("node already running — stop it first".into());
    }

    let dir = PathBuf::from(&data_dir);
    tokio::fs::create_dir_all(&dir)
        .await
        .map_err(|e| format!("data_dir: {e}"))?;

    let label = if side_label.trim().is_empty() {
        "work".to_owned()
    } else {
        side_label.trim().to_owned()
    };
    let master = MasterKey::generate().map_err(|e| e.to_string())?;
    let side = master
        .derive_side(&label.clone().into())
        .map_err(|e| e.to_string())?;
    let side_pk = side.public_bytes();
    let side_address = Address::new(AddressKind::Side, side_pk).encode();

    let listen = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let node = Arc::new(
        Node::start(side, listen, &dir)
            .await
            .map_err(|e| format!("Node::start: {e}"))?,
    );
    let listen_addr = node.listen_addr();
    *guard = Some(node.clone());
    drop(guard);

    // Phase 3.A: open the persistent inbox alongside the side store.
    let inbox = Arc::new(InboxStore::open(&dir).map_err(|e| format!("inbox open: {e}"))?);
    {
        let mut ig = state.inbox.lock().await;
        *ig = Some(inbox.clone());
    }

    // Spawn a drain task that forwards inbound DMs to the frontend AND
    // persists them. The event payload includes `to` so the UI can
    // label which hosted side received the DM (Phase 3.B multi-side).
    let node_for_drain = node.clone();
    let app_for_drain = app.clone();
    let inbox_for_drain = inbox.clone();
    tokio::spawn(async move {
        while let Some(dm) = node_for_drain.next_direct_message().await {
            let plaintext = String::from_utf8_lossy(&dm.plaintext).into_owned();
            let from = Address::new(AddressKind::Side, dm.envelope.from).encode();
            let to_addr = dm.envelope.to;
            let to = to_addr
                .map(|addr| Address::new(AddressKind::Side, addr).encode())
                .unwrap_or_default();
            // Persist before emitting so a frontend reload sees the row.
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            if let Some(recipient) = to_addr {
                inbox_for_drain.insert(&InboxEntry {
                    to: recipient,
                    from: dm.envelope.from,
                    nonce: dm.envelope.nonce.to_vec(),
                    wire_envelope: dm.envelope.to_wire_bytes(),
                    plaintext: dm.plaintext.clone(),
                    received_at: now,
                });
            }
            let _ = app_for_drain.emit(
                "inbox:dm",
                InboxDm {
                    from,
                    to,
                    plaintext,
                    received_at: now,
                },
            );
        }
    });

    Ok(NodeInfo {
        side_address: side_address.clone(),
        side_address_hex: hex::encode(side_pk),
        listen_addr: listen_addr.to_string(),
    })
}

#[tauri::command]
async fn load_inbox_history(
    side_address: String,
    state: State<'_, AppState>,
) -> Result<Vec<InboxDm>, String> {
    // Phase 3.A: on app reload the frontend asks for what was already
    // persisted for the given hosted side. Newest first per the
    // store's ORDER BY received_at DESC.
    let inbox = {
        let g = state.inbox.lock().await;
        g.as_ref()
            .cloned()
            .ok_or_else(|| "node not started".to_owned())?
    };
    let side_pk = decode_side_address(&side_address)?;
    let entries = inbox
        .list_for(&side_pk)
        .map_err(|e| format!("inbox list: {e}"))?;
    Ok(entries
        .into_iter()
        .map(|e| InboxDm {
            from: Address::new(AddressKind::Side, e.from).encode(),
            to: Address::new(AddressKind::Side, e.to).encode(),
            plaintext: String::from_utf8_lossy(&e.plaintext).into_owned(),
            received_at: e.received_at,
        })
        .collect())
}

#[tauri::command]
async fn stop_node(state: State<'_, AppState>) -> Result<(), String> {
    {
        let mut sg = state.sessions.lock().await;
        sg.clear();
    }
    {
        let mut ig = state.inbox.lock().await;
        *ig = None;
    }
    let mut guard = state.node.lock().await;
    if let Some(node) = guard.take() {
        // Drop our handle; if anyone else holds an Arc the bg task keeps
        // running until they let go. The accept loop is aborted by
        // Node::shutdown.
        match Arc::try_unwrap(node) {
            Ok(node) => node.shutdown().await,
            Err(_) => {
                // Other strong refs exist; best-effort cleanup. In
                // practice (single-window scaffold) this branch won't fire.
            }
        }
    }
    Ok(())
}

#[derive(Serialize, Clone)]
struct ConnectResp {
    from_side: String,
    peer_side: String,
}

#[tauri::command]
async fn connect_peer(
    from_side: String,
    peer_addr: String,
    state: State<'_, AppState>,
) -> Result<ConnectResp, String> {
    let node = {
        let g = state.node.lock().await;
        g.as_ref()
            .cloned()
            .ok_or_else(|| "node not started".to_owned())?
    };
    let addr: SocketAddr = peer_addr
        .trim()
        .parse()
        .map_err(|e: std::net::AddrParseError| e.to_string())?;
    let side_pk = decode_side_address(&from_side)?;
    let session = node
        .dial_from(&side_pk, addr, Intent::Direct)
        .await
        .map_err(|e| format!("dial: {e}"))?;
    let peer_side = Address::new(AddressKind::Side, session.peer_side).encode();
    let mut sg = state.sessions.lock().await;
    sg.insert(from_side.clone(), session);
    Ok(ConnectResp {
        from_side,
        peer_side,
    })
}

fn decode_side_address(encoded: &str) -> Result<[u8; 32], String> {
    let addr = Address::parse(encoded.trim()).map_err(|e| format!("parse side: {e}"))?;
    if addr.kind() != AddressKind::Side {
        return Err("not a side address".to_owned());
    }
    Ok(addr.into_key_bytes())
}

#[derive(Serialize, Clone)]
struct AddSideResp {
    side_address: String,
    listen_addr: String,
}

#[tauri::command]
async fn add_side(label: String, state: State<'_, AppState>) -> Result<AddSideResp, String> {
    let node = {
        let g = state.node.lock().await;
        g.as_ref()
            .cloned()
            .ok_or_else(|| "node not started".to_owned())?
    };
    let label = if label.trim().is_empty() {
        "extra".to_owned()
    } else {
        label.trim().to_owned()
    };
    // Each extra side gets its own master/seed so it has no derivable
    // relationship to the primary — matches the spec's posture that
    // sides are independent identities.
    let master = MasterKey::generate().map_err(|e| e.to_string())?;
    let side = master
        .derive_side(&label.clone().into())
        .map_err(|e| e.to_string())?;
    drop(master);
    let listen = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let (added, addr) = node
        .add_side(side, listen)
        .await
        .map_err(|e| format!("add_side: {e}"))?;
    Ok(AddSideResp {
        side_address: Address::new(AddressKind::Side, added.address).encode(),
        listen_addr: addr.to_string(),
    })
}

#[derive(Serialize, Clone)]
struct HostedSide {
    side_address: String,
    listen_addr: String,
    /// Phase 3.C: lifecycle badge — "Created" / "Active" / "Dormant" / "Retired".
    lifecycle: String,
    is_retired: bool,
}

#[tauri::command]
async fn list_sides(state: State<'_, AppState>) -> Result<Vec<HostedSide>, String> {
    let node = {
        let g = state.node.lock().await;
        g.as_ref()
            .cloned()
            .ok_or_else(|| "node not started".to_owned())?
    };
    let mut out = Vec::new();
    for s in node.sides().await {
        let listen = node
            .side_listen_addr(&s.address)
            .await
            .map(|a| a.to_string())
            .unwrap_or_else(|| "(unknown)".to_owned());
        let lifecycle = format!("{:?}", s.lifecycle().await);
        let is_retired = matches!(s.lifecycle().await, sidevers_net::SideLifecycle::Retired);
        out.push(HostedSide {
            side_address: Address::new(AddressKind::Side, s.address).encode(),
            listen_addr: listen,
            lifecycle,
            is_retired,
        });
    }
    Ok(out)
}

// ---------------------------------------------------------------------
// Phase 3.C — profile + relationships UI surface
// ---------------------------------------------------------------------

#[derive(Serialize, Clone)]
struct ProfileView {
    name: Option<String>,
    bio: Option<String>,
    /// Capability tokens this side accepts (§7.7). Stable identifier
    /// strings — see sidevers_core::messages::profile::capability for
    /// the canonical list.
    capabilities: Vec<String>,
    updated_at: u64,
}

#[tauri::command]
async fn get_profile(
    side_address: String,
    state: State<'_, AppState>,
) -> Result<Option<ProfileView>, String> {
    let node = {
        let g = state.node.lock().await;
        g.as_ref()
            .cloned()
            .ok_or_else(|| "node not started".to_owned())?
    };
    let side_pk = decode_side_address(&side_address)?;
    let side = node
        .side_by_address(&side_pk)
        .await
        .ok_or_else(|| "side not hosted on this node".to_owned())?;
    Ok(side.profile().await.map(|p| ProfileView {
        name: p.name.clone(),
        bio: p.bio.clone(),
        capabilities: p.capabilities.iter().cloned().collect(),
        updated_at: p.updated_at,
    }))
}

#[tauri::command]
async fn set_profile(
    side_address: String,
    name: Option<String>,
    bio: Option<String>,
    capabilities: Vec<String>,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let node = {
        let g = state.node.lock().await;
        g.as_ref()
            .cloned()
            .ok_or_else(|| "node not started".to_owned())?
    };
    let side_pk = decode_side_address(&side_address)?;
    let side = node
        .side_by_address(&side_pk)
        .await
        .ok_or_else(|| "side not hosted on this node".to_owned())?;
    let side_key = side.keypair_arc();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let caps: BTreeSet<String> = capabilities.into_iter().collect();
    let payload = ProfilePayload::sign(&side_key, name, None, bio, None, None, caps, now)
        .map_err(|e| format!("sign profile: {e}"))?;
    side.set_profile(payload).await;
    Ok(())
}

#[derive(Serialize, Clone)]
struct RelationshipView {
    address: String,
    nickname: Option<String>,
    capabilities: Vec<String>,
    notes: Option<String>,
    pinned: bool,
    added_at: u64,
    /// Phase 3 Stage C: cached dial endpoint for this contact. `None`
    /// means the UI must prompt before the first chat attempt.
    peer_listen_addr: Option<String>,
}

#[tauri::command]
async fn list_relationships(
    side_address: String,
    state: State<'_, AppState>,
) -> Result<Vec<RelationshipView>, String> {
    let node = {
        let g = state.node.lock().await;
        g.as_ref()
            .cloned()
            .ok_or_else(|| "node not started".to_owned())?
    };
    let side_pk = decode_side_address(&side_address)?;
    let side = node
        .side_by_address(&side_pk)
        .await
        .ok_or_else(|| "side not hosted on this node".to_owned())?;
    Ok(side
        .list_relationships()
        .await
        .into_iter()
        .map(|r| RelationshipView {
            address: Address::new(AddressKind::Side, r.address).encode(),
            nickname: r.nickname,
            capabilities: r.capabilities.iter().cloned().collect(),
            notes: r.notes,
            pinned: r.pinned,
            added_at: r.added_at,
            peer_listen_addr: r.peer_listen_addr,
        })
        .collect())
}

// add_relationship_cmd extended (Phase 3 Stage C): final `peer_listen_addr`
// param is the network endpoint to dial when starting a chat. The chat-first
// UI passes it when known (e.g. from a freshly-scanned ContactCard); callers
// without that info pass `None` and the UI prompts on first chat.
#[tauri::command]
async fn add_relationship_cmd(
    side_address: String,
    peer_address: String,
    nickname: Option<String>,
    capabilities: Vec<String>,
    peer_listen_addr: Option<String>,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let node = {
        let g = state.node.lock().await;
        g.as_ref()
            .cloned()
            .ok_or_else(|| "node not started".to_owned())?
    };
    let side_pk = decode_side_address(&side_address)?;
    let side = node
        .side_by_address(&side_pk)
        .await
        .ok_or_else(|| "side not hosted on this node".to_owned())?;
    let peer_pk = decode_side_address(&peer_address)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let r = SideRelationship {
        address: peer_pk,
        nickname,
        introduced_by: None,
        capabilities: capabilities.into_iter().collect(),
        notes: None,
        pinned: false,
        added_at: now,
        peer_listen_addr,
    };
    side.add_relationship(r).await;
    Ok(())
}

/// Update only the cached network endpoint for an existing
/// relationship. Phase 3 Stage C — the chat UI calls this after the
/// user fills in a peer's listen addr (e.g. after the first manual
/// connect on a relationship that had `peer_listen_addr = None`).
#[tauri::command]
async fn update_relationship_endpoint(
    side_address: String,
    peer_address: String,
    peer_listen_addr: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let node = {
        let g = state.node.lock().await;
        g.as_ref()
            .cloned()
            .ok_or_else(|| "node not started".to_owned())?
    };
    let side_pk = decode_side_address(&side_address)?;
    let side = node
        .side_by_address(&side_pk)
        .await
        .ok_or_else(|| "side not hosted on this node".to_owned())?;
    let peer_pk = decode_side_address(&peer_address)?;
    let addr = peer_listen_addr.trim();
    if addr.is_empty() {
        return Err("peer_listen_addr cannot be empty".to_owned());
    }
    // Validate socket-address shape — easier to reject here than at
    // dial time. (Domain names aren't accepted by SocketAddr::parse;
    // the desktop UI is IP:port-only for now.)
    let _: SocketAddr = addr
        .parse()
        .map_err(|e: std::net::AddrParseError| e.to_string())?;
    let updated = side
        .update_relationship(&peer_pk, |r| {
            r.peer_listen_addr = Some(addr.to_owned());
        })
        .await;
    if updated.is_none() {
        return Err("no such relationship for this side".to_owned());
    }
    Ok(())
}

#[tauri::command]
async fn remove_relationship_cmd(
    side_address: String,
    peer_address: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let node = {
        let g = state.node.lock().await;
        g.as_ref()
            .cloned()
            .ok_or_else(|| "node not started".to_owned())?
    };
    let side_pk = decode_side_address(&side_address)?;
    let side = node
        .side_by_address(&side_pk)
        .await
        .ok_or_else(|| "side not hosted on this node".to_owned())?;
    let peer_pk = decode_side_address(&peer_address)?;
    side.remove_relationship(&peer_pk).await;
    Ok(())
}

#[derive(Serialize, Clone)]
struct RetireResp {
    side_address: String,
    retired_at: u64,
}

#[tauri::command]
async fn retire_side_cmd(
    side_address: String,
    reason: Option<String>,
    state: State<'_, AppState>,
) -> Result<RetireResp, String> {
    let node = {
        let g = state.node.lock().await;
        g.as_ref()
            .cloned()
            .ok_or_else(|| "node not started".to_owned())?
    };
    let side_pk = decode_side_address(&side_address)?;
    let record = node
        .retire_side(&side_pk, reason)
        .await
        .map_err(|e| format!("retire_side: {e}"))?;
    Ok(RetireResp {
        side_address: Address::new(AddressKind::Side, record.side).encode(),
        retired_at: record.retired_at,
    })
}

#[derive(Serialize, Clone)]
struct PairingQrResp {
    uri: String,
    svg: String,
}

#[tauri::command]
async fn generate_pairing_qr_svg(
    side_address: String,
    state: State<'_, AppState>,
) -> Result<PairingQrResp, String> {
    let node = {
        let g = state.node.lock().await;
        g.as_ref()
            .cloned()
            .ok_or_else(|| "node not started".to_owned())?
    };
    let side_pk = decode_side_address(&side_address)?;
    let qr = node
        .generate_pairing_qr(&side_pk)
        .await
        .map_err(|e| format!("generate_pairing_qr: {e}"))?;
    let uri = qr.encode();
    let svg = qrcode::QrCode::new(uri.as_bytes())
        .map_err(|e| format!("qrcode: {e}"))?
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(240, 240)
        .quiet_zone(true)
        .build();
    Ok(PairingQrResp { uri, svg })
}

#[derive(Serialize, Clone)]
struct PairingAcceptResp {
    joined_side: String,
    listen_addr: String,
}

#[tauri::command]
async fn accept_pairing_qr(
    qr_uri: String,
    state: State<'_, AppState>,
) -> Result<PairingAcceptResp, String> {
    let node = {
        let g = state.node.lock().await;
        g.as_ref()
            .cloned()
            .ok_or_else(|| "node not started".to_owned())?
    };
    let qr = PairingQr::parse(qr_uri.trim()).map_err(|e| format!("parse QR: {e}"))?;
    let (side, listen) = node
        .accept_pairing(qr)
        .await
        .map_err(|e| format!("accept_pairing: {e}"))?;
    Ok(PairingAcceptResp {
        joined_side: Address::new(AddressKind::Side, side.address).encode(),
        listen_addr: listen.to_string(),
    })
}

// ---------------------------------------------------------------------
// Phase 3 Stage C — ContactCard ("share me as a friend") QR
// ---------------------------------------------------------------------
// Distinct from PairingQr in that ContactCard carries no secrets —
// just the side's public address + listen endpoint + an optional
// display-name/side-label hint. Receiving it installs a relationship,
// not a co-holder.

#[derive(Serialize, Clone)]
struct ContactQrResp {
    uri: String,
    svg: String,
    /// What was packed into the QR (so the frontend can render a
    /// preview without re-parsing).
    display_name: Option<String>,
    side_label: Option<String>,
}

#[tauri::command]
async fn generate_contact_qr_svg(
    side_address: String,
    state: State<'_, AppState>,
) -> Result<ContactQrResp, String> {
    let node = {
        let g = state.node.lock().await;
        g.as_ref()
            .cloned()
            .ok_or_else(|| "node not started".to_owned())?
    };
    let side_pk = decode_side_address(&side_address)?;
    let side = node
        .side_by_address(&side_pk)
        .await
        .ok_or_else(|| "side not hosted on this node".to_owned())?;
    let dial_addr = node
        .side_listen_addr(&side_pk)
        .await
        .ok_or_else(|| "side has no listen address".to_owned())?
        .to_string();
    let profile = side.profile().await;
    let display_name = profile.as_ref().and_then(|p| p.name.clone());
    let side_label = side.label.clone();
    let card = ContactCard {
        side: side_pk,
        dial_addr,
        display_name: display_name.clone(),
        side_label: side_label.clone(),
    };
    let uri = card.encode();
    let svg = qrcode::QrCode::new(uri.as_bytes())
        .map_err(|e| format!("qrcode: {e}"))?
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(240, 240)
        .quiet_zone(true)
        .build();
    Ok(ContactQrResp {
        uri,
        svg,
        display_name,
        side_label,
    })
}

#[derive(Serialize, Clone)]
struct ContactAcceptResp {
    friend_address: String,
    friend_dial_addr: String,
    display_name: Option<String>,
    side_label: Option<String>,
}

/// Parse a `sidevers-contact:1:` URI and save the carried contact as
/// a relationship on the named hosted side. The new relationship
/// gets `capabilities = ["direct-message"]` by default and the QR's
/// `display_name` (if any) as nickname.
#[tauri::command]
async fn accept_contact_qr(
    side_address: String,
    qr_uri: String,
    state: State<'_, AppState>,
) -> Result<ContactAcceptResp, String> {
    let node = {
        let g = state.node.lock().await;
        g.as_ref()
            .cloned()
            .ok_or_else(|| "node not started".to_owned())?
    };
    let card = ContactCard::parse(qr_uri.trim()).map_err(|e| format!("parse contact QR: {e}"))?;
    let side_pk = decode_side_address(&side_address)?;
    let side = node
        .side_by_address(&side_pk)
        .await
        .ok_or_else(|| "side not hosted on this node".to_owned())?;
    // Refuse to friend yourself — UI should also gate this, but
    // belt-and-braces.
    if side.address == card.side {
        return Err("can't add yourself as a contact".to_owned());
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut caps = BTreeSet::new();
    caps.insert("direct-message".to_owned());
    let rel = SideRelationship {
        address: card.side,
        nickname: card.display_name.clone(),
        introduced_by: None,
        capabilities: caps,
        notes: None,
        pinned: false,
        added_at: now,
        peer_listen_addr: Some(card.dial_addr.clone()),
    };
    side.add_relationship(rel).await;
    Ok(ContactAcceptResp {
        friend_address: Address::new(AddressKind::Side, card.side).encode(),
        friend_dial_addr: card.dial_addr,
        display_name: card.display_name,
        side_label: card.side_label,
    })
}

#[tauri::command]
async fn send_dm_live(
    from_side: String,
    text: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let node = {
        let g = state.node.lock().await;
        g.as_ref()
            .cloned()
            .ok_or_else(|| "node not started".to_owned())?
    };
    let side_pk = decode_side_address(&from_side)?;
    let side_arc = node
        .side_by_address(&side_pk)
        .await
        .ok_or_else(|| "side not hosted on this node".to_owned())?;
    let side_key = side_arc.keypair_arc();
    let sg = state.sessions.lock().await;
    let session = sg
        .get(&from_side)
        .ok_or_else(|| format!("no peer connected from side {from_side}"))?;
    send_dm_helper(session, &side_key, text.as_bytes())
        .await
        .map_err(|e| format!("send_dm: {e}"))?;
    Ok(())
}

// ---------------------------------------------------------------------
// Phase 3 Stage D L2a — Group sides (verses) on the rail
// ---------------------------------------------------------------------
//
// A "group" in the user-facing UI is a verse (protocol §7.7) plus the
// local side identity that represents the user inside that verse. Both
// pieces are minted fresh per group so unlinkability is preserved:
// your work group's pubkey is unrelated to your personal side.
//
// create_group mints both (verse-side hosts the verse, member-side
// participates as moderator), wires them up locally, persists a
// VerseMembershipRecord with role="moderator" + the verse seed +
// contract bytes so restart can re-host. join_group_by_invite mints
// just a member-side, dials the moderator, sends a JoinRequest, and
// persists with role="member".

#[derive(Serialize, Clone)]
struct GroupView {
    /// Bech32 sv1q address of the verse.
    verse_address: String,
    /// Bech32 sv1q address of OUR side in this group (member-side).
    /// All posting / leaving operates from this side.
    member_side_address: String,
    /// "moderator" iff we host this verse locally, "member" otherwise.
    role: String,
    /// Group display name from the contract (hint only).
    name: Option<String>,
    /// Hex-encoded BLAKE3 of the group photo if the moderator set one.
    photo_hash_hex: Option<String>,
    /// Where the verse host listens. Set for member-role rows from the
    /// invite; moderator-role rows record the local listener.
    dial_addr: Option<String>,
    /// Unix-seconds join timestamp.
    joined_at: u64,
}

/// List every group across every local side. The frontend calls this
/// on boot + after every create/join/leave to refresh the rail.
#[tauri::command]
async fn list_groups(data_dir: String) -> Result<Vec<GroupView>, String> {
    let dir = PathBuf::from(&data_dir);
    if !dir.join("sides.db").exists() {
        return Ok(Vec::new());
    }
    let store = SideStore::open(&dir)
        .await
        .map_err(|e| format!("opening side store: {e}"))?;
    let rows = store
        .list_all_verse_memberships()
        .await
        .map_err(|e| format!("list memberships: {e}"))?;
    let mut out = Vec::with_capacity(rows.len());
    for (side, m) in rows {
        out.push(GroupView {
            verse_address: Address::new(AddressKind::Verse, m.verse_address).encode(),
            member_side_address: Address::new(AddressKind::Side, side).encode(),
            role: m.role,
            name: m.name,
            photo_hash_hex: m.photo_hash.map(hex::encode),
            dial_addr: m.dial_addr,
            joined_at: m.joined_at,
        });
    }
    Ok(out)
}

#[derive(Serialize, Clone)]
struct CreateGroupResp {
    verse_address: String,
    member_side_address: String,
    listen_addr: String,
    /// `sidevers-group:1:<base32>` URI for sharing with people you
    /// want to invite. Frontend renders it as both a copyable text
    /// and a QR code via `generate_group_invite_svg`.
    group_invite_uri: String,
}

/// Create a brand-new group. Mints two fresh sides — the verse's
/// identity + the user's identity inside that verse — wires up a
/// VerseHost, persists everything to SideStore.
#[tauri::command]
async fn create_group(
    data_dir: String,
    name: String,
    state: State<'_, AppState>,
) -> Result<CreateGroupResp, String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err("group name cannot be empty".into());
    }
    if trimmed.len() > 256 {
        return Err("group name too long (max 256 chars)".into());
    }
    let node = {
        let g = state.node.lock().await;
        g.as_ref()
            .cloned()
            .ok_or_else(|| "node not started".to_owned())?
    };
    let dir = PathBuf::from(&data_dir);

    // Mint the verse identity (the keypair the verse is "signed by").
    let verse_master = MasterKey::generate().map_err(|e| e.to_string())?;
    let verse_key = verse_master
        .derive_side(&format!("verse-{trimmed}").into())
        .map_err(|e| e.to_string())?;
    let verse_pubkey = verse_key.public_bytes();
    let verse_seed = verse_key.to_seed();

    // Mint the moderator's side-as-participant inside this group.
    let member_master = MasterKey::generate().map_err(|e| e.to_string())?;
    let member_key = member_master
        .derive_side(&format!("group-{trimmed}").into())
        .map_err(|e| e.to_string())?;
    let member_pubkey = member_key.public_bytes();

    // Host the member-side on the node so they get a QUIC endpoint.
    // This persists the side via Node::add_side → Side::load_or_create
    // → SideStore.upsert_side, so restart sees it.
    let listen = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let (_member_side, member_listen) = node
        .add_side(member_key, listen)
        .await
        .map_err(|e| format!("add_side: {e}"))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Minimal contract: title=trimmed, no required/optional fields,
    // no policies, single moderator. Phase 1.5+ amendments can add
    // policies / required fields later via VerseAmend.
    let contract = ContractObject::sign(
        &verse_key,
        1,
        trimmed.to_owned(),
        String::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        vec![member_pubkey],
        now,
    )
    .map_err(|e| format!("contract sign: {e}"))?;
    let contract_hash = contract.hash();
    let contract_wire = contract.to_wire_bytes();
    let content_key = VerseContentKey::generate().map_err(|e| format!("content key: {e}"))?;

    let host = VerseHost::new(verse_key, contract, content_key);
    node.host_verse(host.clone()).await;

    // Add the moderator as a local member of their own verse (no QUIC
    // round-trip). add_local_member returns the same (token, key) pair
    // a remote member would receive via JoinAccept.
    let (membership_token, content_key_bytes) = host
        .add_local_member(member_pubkey, now)
        .await
        .map_err(|e| format!("add_local_member: {e}"))?;

    // Persist the membership row so the group survives a restart.
    let store = SideStore::open(&dir)
        .await
        .map_err(|e| format!("opening side store: {e}"))?;
    let record = VerseMembershipRecord {
        verse_address: verse_pubkey,
        contract_hash,
        membership_token,
        content_key: content_key_bytes,
        joined_at: now,
        role: "moderator".to_owned(),
        name: Some(trimmed.to_owned()),
        photo_hash: None,
        dial_addr: Some(member_listen.to_string()),
        verse_seed: Some(verse_seed),
        contract_wire: Some(contract_wire),
    };
    store
        .upsert_verse_membership(&member_pubkey, &record)
        .await
        .map_err(|e| format!("persist membership: {e}"))?;

    let invite = GroupInvite {
        verse: verse_pubkey,
        contract_hash,
        dial_addr: member_listen.to_string(),
        name: Some(trimmed.to_owned()),
        photo_hash: None,
    };

    Ok(CreateGroupResp {
        verse_address: Address::new(AddressKind::Verse, verse_pubkey).encode(),
        member_side_address: Address::new(AddressKind::Side, member_pubkey).encode(),
        listen_addr: member_listen.to_string(),
        group_invite_uri: invite.encode(),
    })
}

#[derive(Serialize, Clone)]
struct JoinGroupResp {
    verse_address: String,
    member_side_address: String,
    listen_addr: String,
    name: Option<String>,
}

/// Parse a `sidevers-group:1:` URI, mint a fresh member-side, dial the
/// moderator, run the JoinRequest/Accept handshake, persist the
/// resulting VerseMembership.
#[tauri::command]
async fn join_group_by_invite(
    data_dir: String,
    qr_uri: String,
    state: State<'_, AppState>,
) -> Result<JoinGroupResp, String> {
    let invite =
        GroupInvite::parse(qr_uri.trim()).map_err(|e| format!("parse group invite: {e}"))?;
    let node = {
        let g = state.node.lock().await;
        g.as_ref()
            .cloned()
            .ok_or_else(|| "node not started".to_owned())?
    };
    let dir = PathBuf::from(&data_dir);

    // Pseudonymous-per-group: mint a brand-new side for this membership.
    let label = invite
        .name
        .as_deref()
        .map(|n| format!("group-{n}"))
        .unwrap_or_else(|| "group-side".to_owned());
    let member_master = MasterKey::generate().map_err(|e| e.to_string())?;
    let member_key = member_master
        .derive_side(&label.clone().into())
        .map_err(|e| e.to_string())?;
    let member_pubkey = member_key.public_bytes();

    // Add the side to the node so it has a listening endpoint.
    // add_side consumes the SideKey but the returned Arc<Side>
    // re-exposes it via `keypair_arc()`, which the protocol helpers
    // (fetch_contract, request_join, leave_verse, post_to_verse)
    // accept as `&SideKey`.
    let listen = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let (member_side, member_listen) = node
        .add_side(member_key, listen)
        .await
        .map_err(|e| format!("add_side: {e}"))?;
    let member_key_arc = member_side.keypair_arc();

    let dial: SocketAddr = invite
        .dial_addr
        .parse()
        .map_err(|e: std::net::AddrParseError| format!("bad dial_addr: {e}"))?;
    let session = node
        .dial_from(&member_pubkey, dial, Intent::Verse)
        .await
        .map_err(|e| format!("dial verse: {e}"))?;

    // Fetch the contract so we can verify the invite's hash matches
    // and consent to a known version. fetch_contract is exported from
    // sidevers-net::node.
    let contract = sidevers_net::fetch_contract(&session, &member_key_arc)
        .await
        .map_err(|e| format!("fetch contract: {e}"))?;
    if contract.verse != invite.verse {
        return Err("fetched contract is for a different verse than invited".into());
    }
    if contract.hash() != invite.contract_hash {
        return Err("contract hash mismatch — invite is stale or tampered".into());
    }

    // Empty fields for now; contract has no required fields in MVP.
    let fields = std::collections::BTreeMap::new();
    let membership = sidevers_net::request_join(&session, &member_key_arc, &contract, fields)
        .await
        .map_err(|e| format!("join: {e}"))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let store = SideStore::open(&dir)
        .await
        .map_err(|e| format!("opening side store: {e}"))?;
    let mut content_key = [0u8; 32];
    content_key.copy_from_slice(membership.content_key.as_bytes());
    let record = VerseMembershipRecord {
        verse_address: invite.verse,
        contract_hash: membership.contract_hash,
        membership_token: membership.membership_token,
        content_key,
        joined_at: now,
        role: "member".to_owned(),
        name: invite.name.clone(),
        photo_hash: invite.photo_hash,
        dial_addr: Some(invite.dial_addr.clone()),
        verse_seed: None,
        contract_wire: None,
    };
    store
        .upsert_verse_membership(&member_pubkey, &record)
        .await
        .map_err(|e| format!("persist membership: {e}"))?;

    Ok(JoinGroupResp {
        verse_address: Address::new(AddressKind::Verse, invite.verse).encode(),
        member_side_address: Address::new(AddressKind::Side, member_pubkey).encode(),
        listen_addr: member_listen.to_string(),
        name: invite.name,
    })
}

/// Send a plaintext post to a group. The frontend passes the
/// member-side address (the side we joined the verse as); we look
/// up the membership row to get the content key + verse address +
/// dial address, dial the verse host (or reuse a cached session in
/// a later round), and send a VersePost envelope.
#[tauri::command]
async fn post_to_group(
    data_dir: String,
    member_side_address: String,
    text: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let node = {
        let g = state.node.lock().await;
        g.as_ref()
            .cloned()
            .ok_or_else(|| "node not started".to_owned())?
    };
    let dir = PathBuf::from(&data_dir);
    let store = SideStore::open(&dir)
        .await
        .map_err(|e| format!("opening side store: {e}"))?;
    let member_pubkey = decode_side_address(&member_side_address)?;
    let memberships = store
        .list_all_verse_memberships()
        .await
        .map_err(|e| format!("list memberships: {e}"))?;
    let (_, record) = memberships
        .into_iter()
        .find(|(side, _)| *side == member_pubkey)
        .ok_or_else(|| "no group membership for that side".to_owned())?;

    let side_arc = node
        .side_by_address(&member_pubkey)
        .await
        .ok_or_else(|| "side not hosted on this node".to_owned())?;
    let side_key = side_arc.keypair_arc();

    let dial: SocketAddr = record
        .dial_addr
        .ok_or_else(|| "no dial address recorded for this group".to_owned())?
        .parse()
        .map_err(|e: std::net::AddrParseError| format!("bad dial_addr: {e}"))?;

    // Reconstruct the in-memory VerseMembership the protocol API wants.
    // Note: we re-derive content_key from stored bytes; this avoids
    // depending on internal layout of sidevers-net's VerseMembership.
    let membership = sidevers_net::VerseMembership {
        verse: record.verse_address,
        contract_hash: record.contract_hash,
        membership_token: record.membership_token,
        content_key: VerseContentKey::from_bytes(record.content_key),
    };

    let session = node
        .dial_from(&member_pubkey, dial, Intent::Verse)
        .await
        .map_err(|e| format!("dial verse: {e}"))?;
    post_to_verse(&session, &side_key, &membership, text.as_bytes())
        .await
        .map_err(|e| format!("post: {e}"))?;
    Ok(())
}

#[derive(Serialize, Clone)]
struct LeaveGroupResp {
    verse_address: String,
}

/// Leave a group. Sends a VerseLeave envelope to the moderator (so
/// they remove us from the live members set), then deletes the local
/// VerseMembershipRecord. Disposition is hardcoded to "archive" —
/// our local posts stay readable; retract semantics are an advanced
/// option for a later round.
#[tauri::command]
async fn leave_group(
    data_dir: String,
    member_side_address: String,
    state: State<'_, AppState>,
) -> Result<LeaveGroupResp, String> {
    let node = {
        let g = state.node.lock().await;
        g.as_ref()
            .cloned()
            .ok_or_else(|| "node not started".to_owned())?
    };
    let dir = PathBuf::from(&data_dir);
    let store = SideStore::open(&dir)
        .await
        .map_err(|e| format!("opening side store: {e}"))?;
    let member_pubkey = decode_side_address(&member_side_address)?;
    let memberships = store
        .list_all_verse_memberships()
        .await
        .map_err(|e| format!("list memberships: {e}"))?;
    let (_, record) = memberships
        .into_iter()
        .find(|(side, _)| *side == member_pubkey)
        .ok_or_else(|| "no group membership for that side".to_owned())?;
    let verse_address = record.verse_address;

    // Best-effort: tell the moderator we're leaving. If they're
    // unreachable we still delete the local membership.
    if record.role == "member" {
        if let (Some(dial_str), side_arc) = (
            record.dial_addr.clone(),
            node.side_by_address(&member_pubkey).await,
        ) {
            if let Some(side_arc) = side_arc {
                if let Ok(dial) = dial_str.parse::<SocketAddr>() {
                    if let Ok(session) = node.dial_from(&member_pubkey, dial, Intent::Verse).await {
                        let membership = sidevers_net::VerseMembership {
                            verse: record.verse_address,
                            contract_hash: record.contract_hash,
                            membership_token: record.membership_token,
                            content_key: VerseContentKey::from_bytes(record.content_key),
                        };
                        // Disposition = Retain: our prior posts stay
                        // readable on the moderator's host. Retract is
                        // the right-to-be-forgotten option; we expose
                        // it as a Stage E advanced action.
                        let _ = sidevers_net::leave_verse(
                            &session,
                            &side_arc.keypair_arc(),
                            &membership,
                            sidevers_core::messages::verse::DataDisposition::Retain,
                            None,
                        )
                        .await;
                    }
                }
            }
        }
    }

    store
        .delete_verse_membership(&member_pubkey, &verse_address)
        .await
        .map_err(|e| format!("delete membership: {e}"))?;
    Ok(LeaveGroupResp {
        verse_address: Address::new(AddressKind::Verse, verse_address).encode(),
    })
}

#[derive(Serialize, Clone)]
struct GroupMemberView {
    side_address: String,
}

/// List the members of a verse we host locally (moderator role).
/// Plain members don't have authoritative member-list data —
/// they learn about other members through posts.
#[tauri::command]
async fn list_group_members(
    verse_address: String,
    state: State<'_, AppState>,
) -> Result<Vec<GroupMemberView>, String> {
    let node = {
        let g = state.node.lock().await;
        g.as_ref()
            .cloned()
            .ok_or_else(|| "node not started".to_owned())?
    };
    let verse_pk = {
        let addr = Address::parse(verse_address.trim()).map_err(|e| format!("parse verse: {e}"))?;
        if addr.kind() != AddressKind::Verse {
            return Err("not a verse address".into());
        }
        addr.into_key_bytes()
    };
    let host = node
        .hosted_verse(&verse_pk)
        .await
        .ok_or_else(|| "this verse isn't hosted on this node (member view)".to_owned())?;
    let members: Vec<[u8; 32]> = host.members().await;
    Ok(members
        .into_iter()
        .map(|pk| GroupMemberView {
            side_address: Address::new(AddressKind::Side, pk).encode(),
        })
        .collect())
}

#[derive(Serialize, Clone)]
struct GroupInviteResp {
    uri: String,
    svg: String,
}

/// Regenerate the invite link for a group we moderate. Joiners scan
/// or paste the URI; same payload as the one returned from
/// `create_group`, refreshed in case the dial address has changed.
#[tauri::command]
async fn generate_group_invite_svg(
    data_dir: String,
    member_side_address: String,
) -> Result<GroupInviteResp, String> {
    let dir = PathBuf::from(&data_dir);
    let store = SideStore::open(&dir)
        .await
        .map_err(|e| format!("opening side store: {e}"))?;
    let member_pubkey = decode_side_address(&member_side_address)?;
    let memberships = store
        .list_all_verse_memberships()
        .await
        .map_err(|e| format!("list memberships: {e}"))?;
    let (_, record) = memberships
        .into_iter()
        .find(|(side, _)| *side == member_pubkey)
        .ok_or_else(|| "no group membership for that side".to_owned())?;
    if record.role != "moderator" {
        return Err("only the group's moderator can generate invites".into());
    }
    let invite = GroupInvite {
        verse: record.verse_address,
        contract_hash: record.contract_hash,
        dial_addr: record.dial_addr.unwrap_or_default(),
        name: record.name,
        photo_hash: record.photo_hash,
    };
    let uri = invite.encode();
    let svg = qrcode::QrCode::new(uri.as_bytes())
        .map_err(|e| format!("qrcode: {e}"))?
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(240, 240)
        .quiet_zone(true)
        .build();
    Ok(GroupInviteResp { uri, svg })
}

// ---------------------------------------------------------------------
// Legacy key-only commands (kept for offline tooling: seal/open without
// a live node, address encoding, etc.). These do NOT touch the network.
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
        DirectBody::ReferenceBytes(_) => {
            Err("media DMs not yet supported in the desktop UI".into())
        }
    }
}

// ---------------------------------------------------------------------
// Entrypoint
// ---------------------------------------------------------------------

fn main() {
    tauri::Builder::default()
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            // Live-node commands (Phase 1.5h: client networking)
            start_node,
            stop_node,
            connect_peer,
            send_dm_live,
            list_sides,
            add_side,
            retire_side_cmd,
            load_inbox_history,
            // Phase 3.C — profile + contacts UI surface
            get_profile,
            set_profile,
            list_relationships,
            add_relationship_cmd,
            remove_relationship_cmd,
            update_relationship_endpoint,
            // Phase 3.D onboarding wizard
            default_data_dir,
            is_onboarded,
            complete_onboarding,
            write_seed_backup,
            // Phase 3 Stage C — settings + chat-first boot
            get_setting,
            set_setting,
            auto_start_node,
            // Multi-device pairing (Phase 3.C)
            generate_pairing_qr_svg,
            accept_pairing_qr,
            // Phase 3 Stage C — "share me as a friend" QR
            generate_contact_qr_svg,
            accept_contact_qr,
            // Phase 3 Stage C polish — per-side profile photo
            set_side_avatar,
            get_side_avatar,
            clear_side_avatar,
            // Phase 3 Stage D L2a — group sides on the rail (verses)
            list_groups,
            create_group,
            join_group_by_invite,
            post_to_group,
            leave_group,
            list_group_members,
            generate_group_invite_svg,
            // Legacy key-only commands (offline tooling)
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
