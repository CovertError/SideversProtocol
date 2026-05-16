//! Per-side state owned by a Node (Phase 1.5f, Track A).
//!
//! A `Side` holds everything one hosted side needs at runtime: its
//! keypair, published profile, observed retired-sides, contact list
//! (relationships), lifecycle state, and (Track C) co-holder bookkeeping.
//! It's the unit of multi-side hosting (Track B): a Node holds many of
//! these in a registry, each on its own QUIC endpoint.
//!
//! Persistence: every mutator writes through to a `SideStore` (SQLite).
//! On `Side::load_or_create`, the per-side row is read from the store if
//! present, so state survives a node restart.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use sidevers_core::messages::device::{DeltaOp, RelationshipRecord};
use sidevers_core::{ProfilePayload, SideKey};
use tokio::sync::Mutex;
use tracing::warn;

use crate::error::Result;
use crate::relationships::{RelationshipTable, SideLifecycle, SideRelationship};
use crate::side_store::{SideStore, StoredSide};

/// Return the current unix-seconds timestamp, or log + return 0 on clock
/// failure. Used for **local-only** state where a missing timestamp is
/// cosmetic (e.g. `added_at` on a relationship, `observed_at` on a
/// retired-sides entry). Wire-protocol timestamps that the receiver
/// validates against freshness MUST propagate the error instead — never
/// use this for envelope construction.
fn now_or_log_zero() -> u64 {
    match sidevers_core::envelope::now_unix_seconds() {
        Ok(t) => t,
        Err(e) => {
            warn!("side: system clock unavailable, using 0: {e}");
            0
        }
    }
}

/// One hosted side's complete state — keypair + signed objects (profile,
/// retirement) + local view (relationships, retired_sides_seen, lifecycle)
/// + co-holders (Track C). Cheap to clone (`Arc`-wrap externally).
pub struct Side {
    /// 32-byte Ed25519 public key — the side's wire address. Stable for
    /// the lifetime of this Side.
    pub address: [u8; 32],
    /// Optional human label like "work" / "private".
    pub label: Option<String>,
    /// Unix seconds the side row was created.
    pub created_at: u64,

    keypair: Arc<SideKey>,
    profile: Mutex<Option<ProfilePayload>>,
    retired_sides_seen: Mutex<HashSet<[u8; 32]>>,
    relationships: RelationshipTable,
    lifecycle: Mutex<SideLifecycle>,
    last_send_at: Mutex<Option<u64>>,
    is_self_retired: Mutex<bool>,
    // Track-C placeholders. Empty in Track A; populated by Track C handlers.
    co_holders: Mutex<HashMap<[u8; 32], CoHolderRecord>>,
    revoked_devices: Mutex<HashSet<[u8; 32]>>,
    pending_pairings: Mutex<HashMap<[u8; 16], PendingPairing>>,
    /// Phase 1.5g: per-co-holder dial address, learned via the
    /// `CoHolderAdded` delta sent right after pairing completes.
    co_holder_addrs: Mutex<HashMap<[u8; 32], String>>,
    store: SideStore,
}

/// Local record of a co-holder device (Track C).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoHolderRecord {
    pub device_pubkey: [u8; 32],
    pub added_at: u64,
    pub added_by: Option<[u8; 32]>,
}

/// In-progress pairing record kept on the existing device until the new
/// device sends a matching `PairingRequest` (Track C). 10-minute TTL.
#[derive(Debug, Clone)]
pub struct PendingPairing {
    pub issued_at: u64,
}

impl Side {
    /// Load existing state for `side_key.public_bytes()` from `store`, or
    /// create a fresh row if none exists. Returns the populated `Side`.
    pub async fn load_or_create(
        side_key: SideKey,
        label: Option<String>,
        store: SideStore,
    ) -> Result<Self> {
        let address = side_key.public_bytes();
        let now = now_or_log_zero();

        match store.load_side(&address).await? {
            Some(s) => {
                // Existing row — load all per-table state into memory.
                let profile = store.load_profile(&address).await?;
                let retired: HashSet<[u8; 32]> = store
                    .list_retired_seen(&address)
                    .await?
                    .into_iter()
                    .collect();
                let relationships = RelationshipTable::new();
                for r in store.list_relationships(&address).await? {
                    relationships.insert(r).await;
                }
                let mut co_holders = HashMap::new();
                for (dev, added_at, added_by) in store.list_co_holders(&address).await? {
                    co_holders.insert(
                        dev,
                        CoHolderRecord {
                            device_pubkey: dev,
                            added_at,
                            added_by,
                        },
                    );
                }
                let revoked: HashSet<[u8; 32]> = store
                    .list_revoked_devices(&address)
                    .await?
                    .into_iter()
                    .collect();
                let mut co_holder_addrs: HashMap<[u8; 32], String> = HashMap::new();
                for (dev, addr) in store.list_co_holder_addrs(&address).await? {
                    co_holder_addrs.insert(dev, addr);
                }

                let lifecycle = parse_lifecycle(&s.lifecycle);
                Ok(Side {
                    address,
                    label: s.label,
                    created_at: s.created_at,
                    keypair: Arc::new(side_key),
                    profile: Mutex::new(profile),
                    retired_sides_seen: Mutex::new(retired),
                    relationships,
                    lifecycle: Mutex::new(lifecycle),
                    last_send_at: Mutex::new(s.last_send_at),
                    is_self_retired: Mutex::new(s.is_self_retired),
                    co_holders: Mutex::new(co_holders),
                    revoked_devices: Mutex::new(revoked),
                    pending_pairings: Mutex::new(HashMap::new()),
                    co_holder_addrs: Mutex::new(co_holder_addrs),
                    store,
                })
            }
            None => {
                // Fresh side: persist the row and return defaults.
                let stored = StoredSide {
                    address,
                    seed: side_key.to_seed(),
                    label: label.clone(),
                    created_at: now,
                    lifecycle: "Created".to_owned(),
                    last_send_at: None,
                    is_self_retired: false,
                };
                store.upsert_side(&stored).await?;
                Ok(Side {
                    address,
                    label,
                    created_at: now,
                    keypair: Arc::new(side_key),
                    profile: Mutex::new(None),
                    retired_sides_seen: Mutex::new(HashSet::new()),
                    relationships: RelationshipTable::new(),
                    lifecycle: Mutex::new(SideLifecycle::Created),
                    last_send_at: Mutex::new(None),
                    is_self_retired: Mutex::new(false),
                    co_holders: Mutex::new(HashMap::new()),
                    revoked_devices: Mutex::new(HashSet::new()),
                    pending_pairings: Mutex::new(HashMap::new()),
                    co_holder_addrs: Mutex::new(HashMap::new()),
                    store,
                })
            }
        }
    }

    pub fn keypair(&self) -> &SideKey {
        &self.keypair
    }

    pub fn keypair_arc(&self) -> Arc<SideKey> {
        self.keypair.clone()
    }

    pub fn relationships(&self) -> &RelationshipTable {
        &self.relationships
    }

    pub fn store(&self) -> &SideStore {
        &self.store
    }

    // -----------------------------------------------------------------
    // Profile (§7.3) — write-through.
    // -----------------------------------------------------------------

    pub async fn set_profile(&self, p: ProfilePayload) {
        // Persist first; in-memory follows so a read after this never sees
        // a more-recent value than the disk has.
        if let Err(e) = self.store.upsert_profile(&self.address, &p).await {
            warn!("side: persist profile failed: {e}");
        }
        let mut g = self.profile.lock().await;
        *g = Some(p);
    }

    pub async fn profile(&self) -> Option<ProfilePayload> {
        self.profile.lock().await.clone()
    }

    // -----------------------------------------------------------------
    // Retired-sides-seen (§7.8 from the observer's POV).
    // -----------------------------------------------------------------

    pub async fn mark_retired_seen(&self, retired: [u8; 32]) {
        let now = now_or_log_zero();
        if let Err(e) = self
            .store
            .add_retired_seen(&self.address, &retired, now)
            .await
        {
            warn!("side: persist retired-seen failed: {e}");
        }
        self.retired_sides_seen.lock().await.insert(retired);
    }

    pub async fn is_retired_seen(&self, addr: &[u8; 32]) -> bool {
        self.retired_sides_seen.lock().await.contains(addr)
    }

    // -----------------------------------------------------------------
    // Relationships (§7.4) — RelationshipTable wrapped with persistence.
    // -----------------------------------------------------------------

    pub async fn add_relationship(&self, r: SideRelationship) {
        if let Err(e) = self.store.upsert_relationship(&self.address, &r).await {
            warn!("side: persist relationship failed: {e}");
        }
        self.relationships.insert(r).await;
    }

    pub async fn remove_relationship(&self, addr: &[u8; 32]) {
        if let Err(e) = self.store.delete_relationship(&self.address, addr).await {
            warn!("side: persist relationship-delete failed: {e}");
        }
        self.relationships.remove(addr).await;
    }

    pub async fn get_relationship(&self, addr: &[u8; 32]) -> Option<SideRelationship> {
        self.relationships.get(addr).await
    }

    pub async fn list_relationships(&self) -> Vec<SideRelationship> {
        self.relationships.list().await
    }

    pub async fn update_relationship<F>(&self, addr: &[u8; 32], f: F) -> Option<SideRelationship>
    where
        F: FnOnce(&mut SideRelationship),
    {
        let before = self.relationships.get(addr).await?;
        let changed = self.relationships.update(addr, f).await;
        if changed {
            if let Some(after) = self.relationships.get(addr).await {
                if let Err(e) = self.store.upsert_relationship(&self.address, &after).await {
                    warn!("side: persist relationship-update failed: {e}");
                }
            }
        }
        Some(before)
    }

    pub async fn relationship_contains(&self, addr: &[u8; 32]) -> bool {
        self.relationships.contains(addr).await
    }

    // -----------------------------------------------------------------
    // Lifecycle (§7.8) and send-touch.
    // -----------------------------------------------------------------

    pub async fn lifecycle(&self) -> SideLifecycle {
        *self.lifecycle.lock().await
    }

    pub async fn set_lifecycle(&self, state: SideLifecycle) {
        {
            let mut g = self.lifecycle.lock().await;
            *g = state;
        }
        self.persist_lifecycle(state).await;
    }

    pub async fn refresh_lifecycle(&self) {
        let current = *self.lifecycle.lock().await;
        if current == SideLifecycle::Retired {
            return;
        }
        let last = *self.last_send_at.lock().await;
        let now = now_or_log_zero();
        let next = SideLifecycle::derive(last, false, now);
        {
            let mut g = self.lifecycle.lock().await;
            *g = next;
        }
        self.persist_lifecycle(next).await;
    }

    /// Stamp `last_send_at` and advance Created → Active on first send.
    pub async fn touch_send(&self) {
        let now = now_or_log_zero();
        {
            let mut g = self.last_send_at.lock().await;
            *g = Some(now);
        }
        let lifecycle = {
            let mut g = self.lifecycle.lock().await;
            if *g == SideLifecycle::Created {
                *g = SideLifecycle::Active;
            }
            *g
        };
        self.persist_last_send_and_lifecycle(Some(now), lifecycle)
            .await;
    }

    /// Mark this side as having published its own retirement record (sets
    /// `is_self_retired` and lifecycle = Retired).
    pub async fn set_self_retired(&self) {
        {
            let mut r = self.is_self_retired.lock().await;
            *r = true;
        }
        self.set_lifecycle(SideLifecycle::Retired).await;
        // Also re-persist the side row to update `is_self_retired`.
        self.persist_side_row().await;
    }

    pub async fn is_self_retired(&self) -> bool {
        *self.is_self_retired.lock().await
    }

    async fn persist_lifecycle(&self, state: SideLifecycle) {
        let now = *self.last_send_at.lock().await;
        let s = StoredSide {
            address: self.address,
            seed: self.keypair.to_seed(),
            label: self.label.clone(),
            created_at: self.created_at,
            lifecycle: lifecycle_label(state).to_owned(),
            last_send_at: now,
            is_self_retired: *self.is_self_retired.lock().await,
        };
        if let Err(e) = self.store.upsert_side(&s).await {
            warn!("side: persist lifecycle failed: {e}");
        }
    }

    async fn persist_last_send_and_lifecycle(&self, last: Option<u64>, lifecycle: SideLifecycle) {
        let s = StoredSide {
            address: self.address,
            seed: self.keypair.to_seed(),
            label: self.label.clone(),
            created_at: self.created_at,
            lifecycle: lifecycle_label(lifecycle).to_owned(),
            last_send_at: last,
            is_self_retired: *self.is_self_retired.lock().await,
        };
        if let Err(e) = self.store.upsert_side(&s).await {
            warn!("side: persist last_send/lifecycle failed: {e}");
        }
    }

    async fn persist_side_row(&self) {
        let last = *self.last_send_at.lock().await;
        let lifecycle = *self.lifecycle.lock().await;
        self.persist_last_send_and_lifecycle(last, lifecycle).await;
    }

    // -----------------------------------------------------------------
    // Co-holders + revoked devices (Track C). API present from Track A so
    // Track C can fill in semantics without further structural changes.
    // -----------------------------------------------------------------

    pub async fn add_co_holder(&self, device_pubkey: [u8; 32], added_by: Option<[u8; 32]>) {
        let added_at = now_or_log_zero();
        if let Err(e) = self
            .store
            .add_co_holder(&self.address, &device_pubkey, added_at, added_by.as_ref())
            .await
        {
            warn!("side: persist co-holder failed: {e}");
        }
        self.co_holders.lock().await.insert(
            device_pubkey,
            CoHolderRecord {
                device_pubkey,
                added_at,
                added_by,
            },
        );
    }

    pub async fn remove_co_holder(&self, device_pubkey: &[u8; 32]) {
        if let Err(e) = self
            .store
            .remove_co_holder(&self.address, device_pubkey)
            .await
        {
            warn!("side: persist co-holder-remove failed: {e}");
        }
        self.co_holders.lock().await.remove(device_pubkey);
    }

    pub async fn list_co_holders(&self) -> Vec<CoHolderRecord> {
        self.co_holders.lock().await.values().cloned().collect()
    }

    pub async fn add_revoked_device(&self, device_pubkey: [u8; 32]) {
        let now = now_or_log_zero();
        if let Err(e) = self
            .store
            .add_revoked_device(&self.address, &device_pubkey, now)
            .await
        {
            warn!("side: persist revoked-device failed: {e}");
        }
        self.revoked_devices.lock().await.insert(device_pubkey);
    }

    pub async fn is_device_revoked(&self, device_pubkey: &[u8; 32]) -> bool {
        self.revoked_devices.lock().await.contains(device_pubkey)
    }

    pub async fn add_pending_pairing(&self, nonce: [u8; 16]) {
        let now = now_or_log_zero();
        self.pending_pairings
            .lock()
            .await
            .insert(nonce, PendingPairing { issued_at: now });
    }

    pub async fn take_pending_pairing(&self, nonce: &[u8; 16]) -> Option<PendingPairing> {
        let now = now_or_log_zero();
        let mut g = self.pending_pairings.lock().await;
        // Sweep stale entries (>600s) opportunistically.
        g.retain(|_, p| now.saturating_sub(p.issued_at) < 600);
        g.remove(nonce)
    }

    // -----------------------------------------------------------------
    // Co-holder dial-address tracking (Phase 1.5g, for delta push).
    // -----------------------------------------------------------------

    /// Record / update the dial address for a co-holder device.
    pub async fn record_co_holder_addr(&self, device_pubkey: [u8; 32], dial_addr: String) {
        let now = now_or_log_zero();
        if let Err(e) = self
            .store
            .upsert_co_holder_addr(&self.address, &device_pubkey, &dial_addr, now)
            .await
        {
            warn!("side: persist co-holder-addr failed: {e}");
        }
        self.co_holder_addrs
            .lock()
            .await
            .insert(device_pubkey, dial_addr);
    }

    /// Look up the dial address of a co-holder device.
    pub async fn co_holder_addr(&self, device_pubkey: &[u8; 32]) -> Option<String> {
        self.co_holder_addrs
            .lock()
            .await
            .get(device_pubkey)
            .cloned()
    }

    /// Snapshot all known co-holder addresses.
    pub async fn list_co_holder_addrs(&self) -> Vec<([u8; 32], String)> {
        self.co_holder_addrs
            .lock()
            .await
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect()
    }

    /// Apply a single inbound `DeltaOp` to this side's local state.
    /// Phase 1.5g: receivers call this from `serve_direct` after verifying
    /// the outer `StateDeltaPayload` signature. Last-write-wins semantics
    /// are applied per op type. All writes go through SideStore (persisted).
    pub async fn apply_delta(&self, op: &DeltaOp, applied_at: u64) {
        match op {
            DeltaOp::ProfileUpdated { profile_wire } => {
                let new_profile = match ProfilePayload::from_wire_bytes(profile_wire) {
                    Ok(p) => p,
                    Err(e) => {
                        warn!("apply_delta: ProfileUpdated decode failed: {e}");
                        return;
                    }
                };
                // LWW by profile.updated_at: replace only if newer (or no current).
                let current = self.profile.lock().await.clone();
                let should_apply = match &current {
                    Some(p) => new_profile.updated_at >= p.updated_at,
                    None => true,
                };
                if should_apply {
                    self.set_profile(new_profile).await;
                }
                let _ = applied_at;
            }
            DeltaOp::ProfileCleared => {
                let mut g = self.profile.lock().await;
                *g = None;
                if let Err(e) = self.store.delete_profile(&self.address).await {
                    warn!("apply_delta: persist profile-clear failed: {e}");
                }
            }
            DeltaOp::RelationshipUpserted { record } => {
                let rel = relationship_from_record(record);
                let existing = self.relationships.get(&record.address).await;
                let should_apply = match existing {
                    Some(e) => rel.added_at >= e.added_at,
                    None => true,
                };
                if should_apply {
                    self.add_relationship(rel).await;
                }
            }
            DeltaOp::RelationshipRemoved { address } => {
                self.remove_relationship(address).await;
            }
            DeltaOp::RetiredObserved { address } => {
                self.mark_retired_seen(*address).await;
            }
            DeltaOp::LifecycleChanged { state } => {
                // Retirement is sticky — don't downgrade.
                if *self.is_self_retired.lock().await {
                    return;
                }
                let lc = match state.as_str() {
                    "Active" => SideLifecycle::Active,
                    "Dormant" => SideLifecycle::Dormant,
                    "Retired" => SideLifecycle::Retired,
                    _ => SideLifecycle::Created,
                };
                self.set_lifecycle(lc).await;
                let _ = applied_at;
            }
            DeltaOp::CoHolderAdded {
                device_pubkey,
                dial_addr,
            } => {
                // Loop / echo guard (audit C5): a CoHolderAdded delta
                // that names the side itself OR a device already marked
                // revoked is silently dropped. The first case prevents
                // adding the side keypair to its own co-holder set
                // (which the existing device's accept_pairing happens to
                // do for itself); the second prevents a revoked device
                // from being re-added by an out-of-date co-holder.
                // Idempotency at apply_delta also means receiving the
                // same op twice is harmless.
                if *device_pubkey == self.address {
                    return;
                }
                if self.revoked_devices.lock().await.contains(device_pubkey) {
                    return;
                }
                self.add_co_holder(*device_pubkey, None).await;
                self.record_co_holder_addr(*device_pubkey, dial_addr.clone())
                    .await;
            }
            DeltaOp::CoHolderRemoved { device_pubkey } => {
                self.remove_co_holder(device_pubkey).await;
                self.add_revoked_device(*device_pubkey).await;
                // Drop the addr too — no longer reachable as a co-holder.
                self.co_holder_addrs.lock().await.remove(device_pubkey);
                if let Err(e) = self
                    .store
                    .remove_co_holder_addr(&self.address, device_pubkey)
                    .await
                {
                    warn!("apply_delta: persist coh-addr-remove failed: {e}");
                }
            }
        }
    }
}

fn relationship_from_record(rec: &RelationshipRecord) -> SideRelationship {
    let caps: std::collections::BTreeSet<String> = rec.capabilities.iter().cloned().collect();
    // RelationshipRecord is the wire-format mirror used in state bundles
    // shipped between co-holders. It does not carry the local-only
    // `peer_listen_addr` cache; new co-holders rediscover endpoints from
    // their own usage. Default to None when reconstructing.
    SideRelationship {
        address: rec.address,
        nickname: rec.nickname.clone(),
        introduced_by: rec.introduced_by,
        capabilities: caps,
        notes: rec.notes.clone(),
        pinned: rec.pinned,
        added_at: rec.added_at,
        peer_listen_addr: None,
    }
}

fn lifecycle_label(s: SideLifecycle) -> &'static str {
    match s {
        SideLifecycle::Created => "Created",
        SideLifecycle::Active => "Active",
        SideLifecycle::Dormant => "Dormant",
        SideLifecycle::Retired => "Retired",
    }
}

fn parse_lifecycle(s: &str) -> SideLifecycle {
    match s {
        "Created" => SideLifecycle::Created,
        "Active" => SideLifecycle::Active,
        "Dormant" => SideLifecycle::Dormant,
        "Retired" => SideLifecycle::Retired,
        _ => SideLifecycle::Created, // forward-compat unknown → safe default
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sidevers_core::keys::MasterKey;

    fn fixture_side() -> SideKey {
        MasterKey::from_seed(&[0x11; 32])
            .derive_side(&"work".into())
            .unwrap()
    }

    fn rebuild_key(seed: &[u8; 32]) -> SideKey {
        SideKey::from_seed(seed, "(test)")
    }

    #[tokio::test]
    async fn load_or_create_minted_fresh() {
        let store = SideStore::open_memory().await.unwrap();
        let key = fixture_side();
        let address = key.public_bytes();
        let side = Side::load_or_create(key, Some("work".into()), store)
            .await
            .unwrap();
        assert_eq!(side.address, address);
        assert_eq!(side.label.as_deref(), Some("work"));
        assert_eq!(side.lifecycle().await, SideLifecycle::Created);
        assert!(side.profile().await.is_none());
    }

    #[tokio::test]
    async fn relationship_persists_through_reload() {
        let store = SideStore::open_memory().await.unwrap();
        let key = fixture_side();
        let seed = key.to_seed();
        let side1 = Side::load_or_create(key, None, store.clone())
            .await
            .unwrap();
        let mut caps = std::collections::BTreeSet::new();
        caps.insert("direct-message".to_owned());
        side1
            .add_relationship(SideRelationship {
                address: [0x99; 32],
                nickname: Some("alice".into()),
                introduced_by: None,
                capabilities: caps,
                notes: None,
                pinned: true,
                added_at: 1_700_000_000,
                peer_listen_addr: None,
            })
            .await;
        drop(side1);

        let key2 = rebuild_key(&seed);
        let side2 = Side::load_or_create(key2, None, store).await.unwrap();
        let r = side2.get_relationship(&[0x99; 32]).await.unwrap();
        assert_eq!(r.nickname.as_deref(), Some("alice"));
        assert!(r.pinned);
    }

    #[tokio::test]
    async fn lifecycle_advances_on_touch_send() {
        let store = SideStore::open_memory().await.unwrap();
        let key = fixture_side();
        let side = Side::load_or_create(key, None, store).await.unwrap();
        assert_eq!(side.lifecycle().await, SideLifecycle::Created);
        side.touch_send().await;
        assert_eq!(side.lifecycle().await, SideLifecycle::Active);
    }

    #[tokio::test]
    async fn self_retirement_persists() {
        let store = SideStore::open_memory().await.unwrap();
        let key = fixture_side();
        let seed = key.to_seed();
        let side1 = Side::load_or_create(key, None, store.clone())
            .await
            .unwrap();
        side1.set_self_retired().await;
        drop(side1);

        let key2 = rebuild_key(&seed);
        let side2 = Side::load_or_create(key2, None, store).await.unwrap();
        assert!(side2.is_self_retired().await);
        assert_eq!(side2.lifecycle().await, SideLifecycle::Retired);
    }
}
