//! SQLite-backed persistence for per-side state (Phase 1.5f, Track A).
//!
//! State that survives a node restart: side seed + label + lifecycle,
//! published profile, relationships, observed retired-sides, co-holders,
//! revoked devices. Everything else (replay cache, active gossip sessions,
//! hosted-verse runtime state) stays in memory — it's either reconstructable
//! or transient.
//!
//! Layout: one SQLite file `<data_dir>/sides.db`. Schema versioned via the
//! `schema_version` table; Phase 1.5f introduces version 1.
//!
//! Concurrency model: all ops are synchronous (rusqlite is sync). The
//! `SideStore` wraps `Arc<Mutex<Connection>>`. Callers in async contexts
//! can either call directly (each op is microseconds for small state) or
//! wrap in `tokio::task::spawn_blocking` if latency-sensitive. Phase 1.5f
//! uses direct calls since side-state updates are low-rate.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

use rusqlite::{Connection, OptionalExtension, params};
use sidevers_core::ProfilePayload;
use tokio::sync::Mutex;

use crate::error::{Error, Result};
use crate::relationships::SideRelationship;

/// Current schema version. Bumped when migrations are added.
/// v1 — Phase 1.5f initial: sides, profiles, retired_sides_seen,
///      relationships, co_holders, revoked_devices.
/// v2 — Phase 1.5g: adds co_holder_addrs (per-side device → dial address)
///      to support live state delta push between co-holders.
/// v3 — Phase 3.D: adds `settings` (key, value) table for small
///      durable preferences (onboarding_completed, active_side, etc).
pub const SCHEMA_VERSION: i64 = 3;

/// Newline character used to separate capability tokens in the
/// relationships.capabilities TEXT column. Capability tokens are
/// identifier-like (§7.7); they will not legitimately contain newlines.
const CAP_SEP: char = '\n';

/// Handle to the per-side SQLite database. Cheap to clone (Arc-wrapped).
#[derive(Clone)]
pub struct SideStore {
    conn: Arc<Mutex<Connection>>,
}

/// In-memory representation of a row loaded from `sides`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSide {
    pub address: [u8; 32],
    pub seed: [u8; 32],
    pub label: Option<String>,
    pub created_at: u64,
    pub lifecycle: String,
    pub last_send_at: Option<u64>,
    pub is_self_retired: bool,
}

impl SideStore {
    /// Open (or create) the per-side database at `<data_dir>/sides.db`,
    /// run migrations, return a handle.
    pub async fn open(data_dir: &Path) -> Result<Self> {
        let path = data_dir.join("sides.db");
        tokio::fs::create_dir_all(data_dir).await.ok();
        // Phase 1.H1 (audit-pass): tighten dir + file to owner-only
        // before SQLite starts writing anything sensitive.
        let _ = crate::fs_perms::lock_down_dir(data_dir);
        let conn = Connection::open(&path).map_err(map_sqlite)?;
        let _ = crate::fs_perms::lock_down_file(&path);
        let store = SideStore {
            conn: Arc::new(Mutex::new(conn)),
        };
        store.run_migrations().await?;
        Ok(store)
    }

    /// Open an in-memory database (for tests).
    #[cfg(test)]
    pub async fn open_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().map_err(map_sqlite)?;
        let store = SideStore {
            conn: Arc::new(Mutex::new(conn)),
        };
        store.run_migrations().await?;
        Ok(store)
    }

    async fn run_migrations(&self) -> Result<()> {
        let conn = self.conn.lock().await;
        // schema_version table is itself versionless — one row, one column.
        conn.execute_batch("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);")
            .map_err(map_sqlite)?;

        let current: Option<i64> = conn
            .query_row("SELECT version FROM schema_version", [], |r| r.get(0))
            .optional()
            .map_err(map_sqlite)?;

        match current {
            None => {
                // Fresh DB → install the latest schema in one shot.
                conn.execute_batch(SCHEMA_V1).map_err(map_sqlite)?;
                conn.execute_batch(SCHEMA_V2_DELTA).map_err(map_sqlite)?;
                conn.execute_batch(SCHEMA_V3_DELTA).map_err(map_sqlite)?;
                conn.execute(
                    "INSERT INTO schema_version (version) VALUES (?1)",
                    params![SCHEMA_VERSION],
                )
                .map_err(map_sqlite)?;
            }
            Some(v) if v < 2 => {
                conn.execute_batch(SCHEMA_V2_DELTA).map_err(map_sqlite)?;
                conn.execute_batch(SCHEMA_V3_DELTA).map_err(map_sqlite)?;
                conn.execute(
                    "UPDATE schema_version SET version = ?1",
                    params![SCHEMA_VERSION],
                )
                .map_err(map_sqlite)?;
            }
            Some(v) if v < 3 => {
                conn.execute_batch(SCHEMA_V3_DELTA).map_err(map_sqlite)?;
                conn.execute(
                    "UPDATE schema_version SET version = ?1",
                    params![SCHEMA_VERSION],
                )
                .map_err(map_sqlite)?;
            }
            Some(_) => {
                // Already at current version (or higher).
            }
        }
        Ok(())
    }

    // ---------------------------------------------------------------
    // `settings` table (Phase 3.D — durable preferences)
    // ---------------------------------------------------------------

    /// Read a single setting by `key`. Returns `None` if absent.
    pub async fn get_setting(&self, key: &str) -> Result<Option<String>> {
        let conn = self.conn.lock().await;
        let val: Option<String> = conn
            .query_row(
                "SELECT value FROM settings WHERE key = ?1",
                params![key],
                |r| r.get(0),
            )
            .optional()
            .map_err(map_sqlite)?;
        Ok(val)
    }

    /// Insert or replace a setting. Settings round-trip as opaque text
    /// (JSON / hex / plain string — caller's choice).
    pub async fn set_setting(&self, key: &str, value: &str) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )
        .map_err(map_sqlite)?;
        Ok(())
    }

    // ---------------------------------------------------------------
    // `sides` table
    // ---------------------------------------------------------------

    pub async fn upsert_side(&self, s: &StoredSide) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO sides (address, seed, label, created_at, lifecycle, last_send_at, is_self_retired)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(address) DO UPDATE SET
                label = excluded.label,
                lifecycle = excluded.lifecycle,
                last_send_at = excluded.last_send_at,
                is_self_retired = excluded.is_self_retired",
            params![
                &s.address[..],
                &s.seed[..],
                s.label.as_deref(),
                s.created_at as i64,
                &s.lifecycle,
                s.last_send_at.map(|n| n as i64),
                s.is_self_retired as i64,
            ],
        )
        .map_err(map_sqlite)?;
        Ok(())
    }

    pub async fn load_side(&self, address: &[u8; 32]) -> Result<Option<StoredSide>> {
        let conn = self.conn.lock().await;
        conn.query_row(
            "SELECT address, seed, label, created_at, lifecycle, last_send_at, is_self_retired
             FROM sides WHERE address = ?1",
            params![&address[..]],
            |r| {
                let addr_bytes: Vec<u8> = r.get(0)?;
                let seed_bytes: Vec<u8> = r.get(1)?;
                let label: Option<String> = r.get(2)?;
                let created_at: i64 = r.get(3)?;
                let lifecycle: String = r.get(4)?;
                let last_send_at: Option<i64> = r.get(5)?;
                let is_self_retired: i64 = r.get(6)?;
                let mut address = [0u8; 32];
                address.copy_from_slice(&addr_bytes);
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&seed_bytes);
                Ok(StoredSide {
                    address,
                    seed,
                    label,
                    created_at: created_at as u64,
                    lifecycle,
                    last_send_at: last_send_at.map(|v| v as u64),
                    is_self_retired: is_self_retired != 0,
                })
            },
        )
        .optional()
        .map_err(map_sqlite)
    }

    pub async fn list_sides(&self) -> Result<Vec<StoredSide>> {
        let conn = self.conn.lock().await;
        let mut stmt = conn
            .prepare(
                "SELECT address, seed, label, created_at, lifecycle, last_send_at, is_self_retired
                 FROM sides",
            )
            .map_err(map_sqlite)?;
        let rows = stmt
            .query_map([], |r| {
                let addr_bytes: Vec<u8> = r.get(0)?;
                let seed_bytes: Vec<u8> = r.get(1)?;
                let label: Option<String> = r.get(2)?;
                let created_at: i64 = r.get(3)?;
                let lifecycle: String = r.get(4)?;
                let last_send_at: Option<i64> = r.get(5)?;
                let is_self_retired: i64 = r.get(6)?;
                let mut address = [0u8; 32];
                address.copy_from_slice(&addr_bytes);
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&seed_bytes);
                Ok(StoredSide {
                    address,
                    seed,
                    label,
                    created_at: created_at as u64,
                    lifecycle,
                    last_send_at: last_send_at.map(|v| v as u64),
                    is_self_retired: is_self_retired != 0,
                })
            })
            .map_err(map_sqlite)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(map_sqlite)?);
        }
        Ok(out)
    }

    // ---------------------------------------------------------------
    // `profiles` table
    // ---------------------------------------------------------------

    pub async fn upsert_profile(&self, side: &[u8; 32], profile: &ProfilePayload) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO profiles (side_address, wire_bytes, updated_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(side_address) DO UPDATE SET
                wire_bytes = excluded.wire_bytes,
                updated_at = excluded.updated_at",
            params![
                &side[..],
                profile.to_wire_bytes(),
                profile.updated_at as i64
            ],
        )
        .map_err(map_sqlite)?;
        Ok(())
    }

    pub async fn load_profile(&self, side: &[u8; 32]) -> Result<Option<ProfilePayload>> {
        let conn = self.conn.lock().await;
        let bytes: Option<Vec<u8>> = conn
            .query_row(
                "SELECT wire_bytes FROM profiles WHERE side_address = ?1",
                params![&side[..]],
                |r| r.get(0),
            )
            .optional()
            .map_err(map_sqlite)?;
        match bytes {
            None => Ok(None),
            Some(b) => ProfilePayload::from_wire_bytes(&b)
                .map(Some)
                .map_err(Error::Core),
        }
    }

    pub async fn delete_profile(&self, side: &[u8; 32]) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "DELETE FROM profiles WHERE side_address = ?1",
            params![&side[..]],
        )
        .map_err(map_sqlite)?;
        Ok(())
    }

    // ---------------------------------------------------------------
    // `retired_sides_seen` table
    // ---------------------------------------------------------------

    pub async fn add_retired_seen(
        &self,
        observer: &[u8; 32],
        retired: &[u8; 32],
        observed_at: u64,
    ) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT OR IGNORE INTO retired_sides_seen (observer_address, retired_address, observed_at)
             VALUES (?1, ?2, ?3)",
            params![&observer[..], &retired[..], observed_at as i64],
        )
        .map_err(map_sqlite)?;
        Ok(())
    }

    pub async fn list_retired_seen(&self, observer: &[u8; 32]) -> Result<Vec<[u8; 32]>> {
        let conn = self.conn.lock().await;
        let mut stmt = conn
            .prepare("SELECT retired_address FROM retired_sides_seen WHERE observer_address = ?1")
            .map_err(map_sqlite)?;
        let rows = stmt
            .query_map(params![&observer[..]], |r| {
                let b: Vec<u8> = r.get(0)?;
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                Ok(a)
            })
            .map_err(map_sqlite)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(map_sqlite)?);
        }
        Ok(out)
    }

    // ---------------------------------------------------------------
    // `relationships` table
    // ---------------------------------------------------------------

    pub async fn upsert_relationship(&self, side: &[u8; 32], r: &SideRelationship) -> Result<()> {
        let caps_blob = encode_capabilities(&r.capabilities);
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO relationships (side_address, peer_address, nickname, introduced_by, capabilities, notes, pinned, added_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(side_address, peer_address) DO UPDATE SET
                nickname = excluded.nickname,
                introduced_by = excluded.introduced_by,
                capabilities = excluded.capabilities,
                notes = excluded.notes,
                pinned = excluded.pinned",
            params![
                &side[..],
                &r.address[..],
                r.nickname.as_deref(),
                r.introduced_by.as_ref().map(|b| &b[..]),
                caps_blob,
                r.notes.as_deref(),
                r.pinned as i64,
                r.added_at as i64,
            ],
        )
        .map_err(map_sqlite)?;
        Ok(())
    }

    pub async fn delete_relationship(&self, side: &[u8; 32], peer: &[u8; 32]) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "DELETE FROM relationships WHERE side_address = ?1 AND peer_address = ?2",
            params![&side[..], &peer[..]],
        )
        .map_err(map_sqlite)?;
        Ok(())
    }

    pub async fn list_relationships(&self, side: &[u8; 32]) -> Result<Vec<SideRelationship>> {
        let conn = self.conn.lock().await;
        let mut stmt = conn
            .prepare(
                "SELECT peer_address, nickname, introduced_by, capabilities, notes, pinned, added_at
                 FROM relationships WHERE side_address = ?1",
            )
            .map_err(map_sqlite)?;
        let rows = stmt
            .query_map(params![&side[..]], |r| {
                let peer_bytes: Vec<u8> = r.get(0)?;
                let nickname: Option<String> = r.get(1)?;
                let introduced_by_bytes: Option<Vec<u8>> = r.get(2)?;
                let capabilities: String = r.get(3)?;
                let notes: Option<String> = r.get(4)?;
                let pinned: i64 = r.get(5)?;
                let added_at: i64 = r.get(6)?;

                let mut address = [0u8; 32];
                address.copy_from_slice(&peer_bytes);
                let introduced_by = introduced_by_bytes.map(|b| {
                    let mut a = [0u8; 32];
                    a.copy_from_slice(&b);
                    a
                });
                Ok(SideRelationship {
                    address,
                    nickname,
                    introduced_by,
                    capabilities: decode_capabilities(&capabilities),
                    notes,
                    pinned: pinned != 0,
                    added_at: added_at as u64,
                })
            })
            .map_err(map_sqlite)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(map_sqlite)?);
        }
        Ok(out)
    }

    // ---------------------------------------------------------------
    // `co_holders` table (Track C usage; defined now for completeness)
    // ---------------------------------------------------------------

    pub async fn add_co_holder(
        &self,
        side: &[u8; 32],
        device_pubkey: &[u8; 32],
        added_at: u64,
        added_by: Option<&[u8; 32]>,
    ) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT OR REPLACE INTO co_holders (side_address, device_pubkey, added_at, added_by)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                &side[..],
                &device_pubkey[..],
                added_at as i64,
                added_by.map(|b| &b[..]),
            ],
        )
        .map_err(map_sqlite)?;
        Ok(())
    }

    pub async fn remove_co_holder(&self, side: &[u8; 32], device_pubkey: &[u8; 32]) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "DELETE FROM co_holders WHERE side_address = ?1 AND device_pubkey = ?2",
            params![&side[..], &device_pubkey[..]],
        )
        .map_err(map_sqlite)?;
        Ok(())
    }

    pub async fn list_co_holders(
        &self,
        side: &[u8; 32],
    ) -> Result<Vec<([u8; 32], u64, Option<[u8; 32]>)>> {
        let conn = self.conn.lock().await;
        let mut stmt = conn
            .prepare(
                "SELECT device_pubkey, added_at, added_by FROM co_holders WHERE side_address = ?1",
            )
            .map_err(map_sqlite)?;
        let rows = stmt
            .query_map(params![&side[..]], |r| {
                let dev: Vec<u8> = r.get(0)?;
                let added_at: i64 = r.get(1)?;
                let added_by_bytes: Option<Vec<u8>> = r.get(2)?;
                let mut device_pubkey = [0u8; 32];
                device_pubkey.copy_from_slice(&dev);
                let added_by = added_by_bytes.map(|b| {
                    let mut a = [0u8; 32];
                    a.copy_from_slice(&b);
                    a
                });
                Ok((device_pubkey, added_at as u64, added_by))
            })
            .map_err(map_sqlite)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(map_sqlite)?);
        }
        Ok(out)
    }

    pub async fn add_revoked_device(
        &self,
        side: &[u8; 32],
        device_pubkey: &[u8; 32],
        revoked_at: u64,
    ) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT OR IGNORE INTO revoked_devices (side_address, device_pubkey, revoked_at)
             VALUES (?1, ?2, ?3)",
            params![&side[..], &device_pubkey[..], revoked_at as i64],
        )
        .map_err(map_sqlite)?;
        Ok(())
    }

    pub async fn list_revoked_devices(&self, side: &[u8; 32]) -> Result<Vec<[u8; 32]>> {
        let conn = self.conn.lock().await;
        let mut stmt = conn
            .prepare("SELECT device_pubkey FROM revoked_devices WHERE side_address = ?1")
            .map_err(map_sqlite)?;
        let rows = stmt
            .query_map(params![&side[..]], |r| {
                let b: Vec<u8> = r.get(0)?;
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                Ok(a)
            })
            .map_err(map_sqlite)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(map_sqlite)?);
        }
        Ok(out)
    }

    // ---------------------------------------------------------------
    // `co_holder_addrs` table (Phase 1.5g — live delta push)
    // ---------------------------------------------------------------

    /// Upsert the last-known dial address for a co-holder device. Phase 1.5g.
    pub async fn upsert_co_holder_addr(
        &self,
        side: &[u8; 32],
        device_pubkey: &[u8; 32],
        dial_addr: &str,
        updated_at: u64,
    ) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO co_holder_addrs (side_address, device_pubkey, dial_addr, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(side_address, device_pubkey) DO UPDATE SET
                dial_addr = excluded.dial_addr,
                updated_at = excluded.updated_at",
            params![&side[..], &device_pubkey[..], dial_addr, updated_at as i64],
        )
        .map_err(map_sqlite)?;
        Ok(())
    }

    /// Remove a co-holder's recorded dial address.
    pub async fn remove_co_holder_addr(
        &self,
        side: &[u8; 32],
        device_pubkey: &[u8; 32],
    ) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "DELETE FROM co_holder_addrs WHERE side_address = ?1 AND device_pubkey = ?2",
            params![&side[..], &device_pubkey[..]],
        )
        .map_err(map_sqlite)?;
        Ok(())
    }

    /// Snapshot every co-holder address for `side` as a vec of
    /// `(device_pubkey, dial_addr)` tuples.
    pub async fn list_co_holder_addrs(&self, side: &[u8; 32]) -> Result<Vec<([u8; 32], String)>> {
        let conn = self.conn.lock().await;
        let mut stmt = conn
            .prepare("SELECT device_pubkey, dial_addr FROM co_holder_addrs WHERE side_address = ?1")
            .map_err(map_sqlite)?;
        let rows = stmt
            .query_map(params![&side[..]], |r| {
                let dev_bytes: Vec<u8> = r.get(0)?;
                let dial: String = r.get(1)?;
                let mut dev = [0u8; 32];
                dev.copy_from_slice(&dev_bytes);
                Ok((dev, dial))
            })
            .map_err(map_sqlite)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(map_sqlite)?);
        }
        Ok(out)
    }
}

fn map_sqlite(e: rusqlite::Error) -> Error {
    Error::Sqlite(e.to_string())
}

fn encode_capabilities(caps: &BTreeSet<String>) -> String {
    let mut s = String::new();
    for (i, c) in caps.iter().enumerate() {
        if i > 0 {
            s.push(CAP_SEP);
        }
        s.push_str(c);
    }
    s
}

fn decode_capabilities(s: &str) -> BTreeSet<String> {
    if s.is_empty() {
        return BTreeSet::new();
    }
    s.split(CAP_SEP).map(|c| c.to_owned()).collect()
}

const SCHEMA_V1: &str = r#"
CREATE TABLE IF NOT EXISTS sides (
    address          BLOB PRIMARY KEY,
    seed             BLOB NOT NULL,
    label            TEXT,
    created_at       INTEGER NOT NULL,
    lifecycle        TEXT NOT NULL,
    last_send_at     INTEGER,
    is_self_retired  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS profiles (
    side_address     BLOB PRIMARY KEY REFERENCES sides(address) ON DELETE CASCADE,
    wire_bytes       BLOB NOT NULL,
    updated_at       INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS retired_sides_seen (
    observer_address BLOB NOT NULL REFERENCES sides(address) ON DELETE CASCADE,
    retired_address  BLOB NOT NULL,
    observed_at      INTEGER NOT NULL,
    PRIMARY KEY (observer_address, retired_address)
);

CREATE TABLE IF NOT EXISTS relationships (
    side_address     BLOB NOT NULL REFERENCES sides(address) ON DELETE CASCADE,
    peer_address     BLOB NOT NULL,
    nickname         TEXT,
    introduced_by    BLOB,
    capabilities     TEXT NOT NULL,
    notes            TEXT,
    pinned           INTEGER NOT NULL DEFAULT 0,
    added_at         INTEGER NOT NULL,
    PRIMARY KEY (side_address, peer_address)
);

CREATE TABLE IF NOT EXISTS co_holders (
    side_address     BLOB NOT NULL REFERENCES sides(address) ON DELETE CASCADE,
    device_pubkey    BLOB NOT NULL,
    added_at         INTEGER NOT NULL,
    added_by         BLOB,
    PRIMARY KEY (side_address, device_pubkey)
);

CREATE TABLE IF NOT EXISTS revoked_devices (
    side_address     BLOB NOT NULL REFERENCES sides(address) ON DELETE CASCADE,
    device_pubkey    BLOB NOT NULL,
    revoked_at       INTEGER NOT NULL,
    PRIMARY KEY (side_address, device_pubkey)
);
"#;

/// v1 → v2 migration: add `co_holder_addrs` (per-side device → dial address)
/// for Phase 1.5g live state delta push between co-holders.
const SCHEMA_V2_DELTA: &str = r#"
CREATE TABLE IF NOT EXISTS co_holder_addrs (
    side_address     BLOB NOT NULL REFERENCES sides(address) ON DELETE CASCADE,
    device_pubkey    BLOB NOT NULL,
    dial_addr        TEXT NOT NULL,
    updated_at       INTEGER NOT NULL,
    PRIMARY KEY (side_address, device_pubkey)
);
"#;

/// v2 → v3 migration (Phase 3.D): small (key, value) `settings` table.
/// Used for durable preferences that don't fit any other table —
/// onboarding_completed, last-active-side, theme preference, etc.
/// Values are opaque text; callers serialize/deserialize as needed.
const SCHEMA_V3_DELTA: &str = r#"
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
);
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn rel(addr: u8, caps: &[&str]) -> SideRelationship {
        let mut set = BTreeSet::new();
        for c in caps {
            set.insert((*c).to_owned());
        }
        SideRelationship {
            address: [addr; 32],
            nickname: Some(format!("contact-{}", addr)),
            introduced_by: None,
            capabilities: set,
            notes: None,
            pinned: false,
            added_at: 1_700_000_000,
        }
    }

    #[tokio::test]
    async fn side_round_trip() {
        let store = SideStore::open_memory().await.unwrap();
        let side = StoredSide {
            address: [0x11; 32],
            seed: [0x22; 32],
            label: Some("work".to_owned()),
            created_at: 1_700_000_000,
            lifecycle: "Active".to_owned(),
            last_send_at: Some(1_700_000_100),
            is_self_retired: false,
        };
        store.upsert_side(&side).await.unwrap();
        let got = store.load_side(&[0x11; 32]).await.unwrap().unwrap();
        assert_eq!(got, side);
    }

    #[tokio::test]
    async fn settings_round_trip() {
        let store = SideStore::open_memory().await.unwrap();
        assert!(
            store
                .get_setting("onboarding_completed")
                .await
                .unwrap()
                .is_none()
        );
        store
            .set_setting("onboarding_completed", "true")
            .await
            .unwrap();
        assert_eq!(
            store.get_setting("onboarding_completed").await.unwrap(),
            Some("true".to_owned())
        );
        // Overwrite.
        store
            .set_setting("onboarding_completed", "false")
            .await
            .unwrap();
        assert_eq!(
            store.get_setting("onboarding_completed").await.unwrap(),
            Some("false".to_owned())
        );
    }

    #[tokio::test]
    async fn relationship_round_trip() {
        let store = SideStore::open_memory().await.unwrap();
        store
            .upsert_side(&StoredSide {
                address: [0x11; 32],
                seed: [0x22; 32],
                label: None,
                created_at: 1,
                lifecycle: "Created".to_owned(),
                last_send_at: None,
                is_self_retired: false,
            })
            .await
            .unwrap();
        let r = rel(0x55, &["direct-message", "storage-host"]);
        store.upsert_relationship(&[0x11; 32], &r).await.unwrap();
        let all = store.list_relationships(&[0x11; 32]).await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0], r);
        store
            .delete_relationship(&[0x11; 32], &[0x55; 32])
            .await
            .unwrap();
        assert_eq!(
            store.list_relationships(&[0x11; 32]).await.unwrap().len(),
            0
        );
    }

    #[tokio::test]
    async fn capabilities_encoding_round_trips_through_text_column() {
        let mut caps = BTreeSet::new();
        caps.insert("direct-message".to_owned());
        caps.insert("gossip-relay".to_owned());
        caps.insert("storage-host".to_owned());
        let s = encode_capabilities(&caps);
        let back = decode_capabilities(&s);
        assert_eq!(back, caps);
        // Empty set → empty string → empty set.
        assert!(decode_capabilities("").is_empty());
    }

    #[tokio::test]
    async fn retired_seen_round_trip() {
        let store = SideStore::open_memory().await.unwrap();
        store
            .upsert_side(&StoredSide {
                address: [0x11; 32],
                seed: [0; 32],
                label: None,
                created_at: 1,
                lifecycle: "Active".to_owned(),
                last_send_at: None,
                is_self_retired: false,
            })
            .await
            .unwrap();
        store
            .add_retired_seen(&[0x11; 32], &[0x77; 32], 12345)
            .await
            .unwrap();
        let list = store.list_retired_seen(&[0x11; 32]).await.unwrap();
        assert_eq!(list, vec![[0x77; 32]]);
    }

    #[tokio::test]
    async fn co_holders_and_revocations_round_trip() {
        let store = SideStore::open_memory().await.unwrap();
        store
            .upsert_side(&StoredSide {
                address: [0x11; 32],
                seed: [0; 32],
                label: None,
                created_at: 1,
                lifecycle: "Active".to_owned(),
                last_send_at: None,
                is_self_retired: false,
            })
            .await
            .unwrap();
        store
            .add_co_holder(&[0x11; 32], &[0xAA; 32], 100, None)
            .await
            .unwrap();
        store
            .add_co_holder(&[0x11; 32], &[0xBB; 32], 200, Some(&[0xAA; 32]))
            .await
            .unwrap();
        let coh = store.list_co_holders(&[0x11; 32]).await.unwrap();
        assert_eq!(coh.len(), 2);
        store
            .add_revoked_device(&[0x11; 32], &[0xCC; 32], 300)
            .await
            .unwrap();
        let rev = store.list_revoked_devices(&[0x11; 32]).await.unwrap();
        assert_eq!(rev, vec![[0xCC; 32]]);
    }

    #[tokio::test]
    async fn second_open_reuses_schema() {
        let _store1 = SideStore::open_memory().await.unwrap();
        // For file-based DB this would test re-open; in-memory is per-connection.
        // The migration runner short-circuits on existing schema_version row.
        let store2 = SideStore::open_memory().await.unwrap();
        assert!(store2.list_sides().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn v1_database_migrates_to_v2_without_data_loss() {
        // Build a v1-shaped database by hand (using a fresh in-memory
        // connection, NO migration), insert one row, then re-open via
        // `SideStore::open` on the same path — the migration must add
        // the v2 `co_holder_addrs` table without dropping the row.
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("sides.db");

        // Phase 1: write v1 schema by hand.
        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch(
                "CREATE TABLE schema_version (version INTEGER NOT NULL);
                 INSERT INTO schema_version (version) VALUES (1);",
            )
            .unwrap();
            conn.execute_batch(SCHEMA_V1).unwrap();
            // Insert a synthetic v1 side row.
            conn.execute(
                "INSERT INTO sides (address, seed, label, created_at, lifecycle, last_send_at, is_self_retired)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![
                    &[0xAB_u8; 32][..],
                    &[0xCD_u8; 32][..],
                    Some("legacy"),
                    1_700_000_000_i64,
                    "Active",
                    Option::<i64>::None,
                    0_i64,
                ],
            )
            .unwrap();
        }

        // Phase 2: re-open with the current binary; migration runs.
        let store = SideStore::open(tmp.path()).await.unwrap();

        // The v1 row survives.
        let sides = store.list_sides().await.unwrap();
        assert_eq!(sides.len(), 1);
        assert_eq!(sides[0].address, [0xAB; 32]);
        assert_eq!(sides[0].label.as_deref(), Some("legacy"));

        // The v2 `co_holder_addrs` table is now usable.
        store
            .upsert_co_holder_addr(&[0xAB; 32], &[0xEE; 32], "127.0.0.1:12345", 100)
            .await
            .unwrap();
        let addrs = store.list_co_holder_addrs(&[0xAB; 32]).await.unwrap();
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].0, [0xEE; 32]);
        assert_eq!(addrs[0].1, "127.0.0.1:12345");

        // Schema version is now 2.
        let conn = store.conn.lock().await;
        let v: i64 = conn
            .query_row("SELECT version FROM schema_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, SCHEMA_VERSION);
    }
}
