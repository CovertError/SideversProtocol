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
use std::path::PathBuf;
use std::sync::Arc;

use serde::Serialize;
use sidevers_core::keys::{MasterKey, SECRET_KEY_LEN, SideKey};
use sidevers_core::messages::direct::{DirectBody, DirectKind, DirectMessagePayload};
use sidevers_core::payload as core_payload;
use sidevers_core::{Address, AddressKind, Envelope, MessageType, PairingQr, ProfilePayload};
use sidevers_net::{
    InboxEntry, InboxStore, Intent, Node, Session, SideRelationship, SideStore,
    send_dm as send_dm_helper,
};
use std::collections::BTreeSet;
use tauri::{Emitter, State};
use tokio::sync::Mutex;

/// Key used in the SideStore `settings` table to gate the onboarding
/// wizard. Set to "true" once the first-run flow completes.
const SETTING_ONBOARDING_COMPLETED: &str = "onboarding_completed";

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

/// Write the active node's primary side seed to a user-chosen path,
/// chmod 0o600. The wizard's "Backup seed" step calls this once.
#[tauri::command]
async fn write_seed_backup(
    out_path: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let node = {
        let g = state.node.lock().await;
        g.as_ref()
            .cloned()
            .ok_or_else(|| "node not started — backup must run after start_node".to_owned())?
    };
    let seed = node.side().to_seed();
    let path = PathBuf::from(out_path);
    tokio::fs::write(&path, &seed)
        .await
        .map_err(|e| format!("writing seed file: {e}"))?;
    // Owner-only — matches the CLI's write_secret pattern.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(&path).map_err(|e| e.to_string())?;
        let mut perms = meta.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&path, perms).map_err(|e| e.to_string())?;
    }
    Ok(())
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
            if let Some(recipient) = to_addr {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                inbox_for_drain.insert(&InboxEntry {
                    to: recipient,
                    from: dm.envelope.from,
                    nonce: dm.envelope.nonce.to_vec(),
                    wire_envelope: dm.envelope.to_wire_bytes(),
                    plaintext: dm.plaintext.clone(),
                    received_at: now,
                });
            }
            let _ = app_for_drain.emit("inbox:dm", InboxDm { from, to, plaintext });
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
        let is_retired = matches!(
            s.lifecycle().await,
            sidevers_net::SideLifecycle::Retired
        );
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
        })
        .collect())
}

#[tauri::command]
async fn add_relationship_cmd(
    side_address: String,
    peer_address: String,
    nickname: Option<String>,
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
    };
    side.add_relationship(r).await;
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
            // Phase 3.D onboarding wizard
            default_data_dir,
            is_onboarded,
            complete_onboarding,
            write_seed_backup,
            // Multi-device pairing (Phase 3.C)
            generate_pairing_qr_svg,
            accept_pairing_qr,
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
