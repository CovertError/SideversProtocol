//! Phase 3.A: persistent direct-message inbox.
//!
//! The Tauri drain loop forwards every inbound DM to the frontend as
//! it arrives (`inbox:dm` event). Pre-3.A nothing was retained — if
//! the app quit before the user looked at the chat, the message was
//! gone. This store keeps `(envelope, plaintext, received_at)` rows
//! in a small SQLite table so a fresh app boot can load history.
//!
//! Concurrency mirrors [`crate::replay_journal::SqliteReplayJournal`]:
//! one dedicated rusqlite Connection wrapped in `std::sync::Mutex`,
//! sync method shape so callers from any context (sync or async) can
//! drop in. Writes happen on the hot DM path so we keep them small.
//!
//! Schema (`<data_dir>/sides.db` table `inbox`):
//!
//! ```sql
//! CREATE TABLE IF NOT EXISTS inbox (
//!     "to"        BLOB NOT NULL,  -- recipient side pubkey
//!     "from"      BLOB NOT NULL,  -- sender side pubkey
//!     nonce       BLOB NOT NULL,
//!     wire        BLOB NOT NULL,  -- full Envelope::to_wire_bytes()
//!     plaintext   BLOB NOT NULL,
//!     received_at INTEGER NOT NULL,
//!     PRIMARY KEY ("to", "from", nonce)
//! );
//! ```

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{Connection, params};
use tracing::warn;

use crate::error::{Error, Result};

/// One stored inbox row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboxEntry {
    pub to: [u8; 32],
    pub from: [u8; 32],
    pub nonce: Vec<u8>,
    pub wire_envelope: Vec<u8>,
    pub plaintext: Vec<u8>,
    pub received_at: u64,
}

/// SQLite-backed inbox store. Cheap to clone (Arc-internal).
#[derive(Debug)]
pub struct InboxStore {
    conn: Mutex<Connection>,
}

impl InboxStore {
    /// Open (or create) `<data_dir>/sides.db` and install the inbox table.
    pub fn open(data_dir: &Path) -> Result<Self> {
        let path = data_dir.join("sides.db");
        let conn = Connection::open(&path).map_err(map_sqlite)?;
        // Phase 1.H3 (audit-pass): WAL gives concurrent readers while
        // a write commits; synchronous=NORMAL trades a few-ms fsync
        // for ~1ms per envelope on the hot DM path. NORMAL is still
        // crash-safe — only the last few transactions can vanish.
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;\nPRAGMA synchronous=NORMAL;\nPRAGMA temp_store=MEMORY;",
        )
        .map_err(map_sqlite)?;
        conn.execute_batch(SCHEMA).map_err(map_sqlite)?;
        // Phase 1.H1 (audit-pass): owner-only file mode. Stops other
        // local users from reading plaintext DMs.
        let _ = crate::fs_perms::lock_down_file(&path);
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Insert one received DM. Dedup on `(to, from, nonce)` — replaying
    /// the same envelope (e.g. cache reload) is a no-op.
    pub fn insert(&self, entry: &InboxEntry) {
        let Ok(conn) = self.conn.lock() else { return };
        let _ = conn
            .execute(
                "INSERT OR IGNORE INTO inbox (\"to\", \"from\", nonce, wire, plaintext, received_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    &entry.to[..],
                    &entry.from[..],
                    &entry.nonce[..],
                    &entry.wire_envelope[..],
                    &entry.plaintext[..],
                    entry.received_at as i64,
                ],
            )
            .inspect_err(|e| warn!(error = %e, "inbox: insert failed"));
    }

    /// Load every stored inbox row addressed to `recipient`, newest first.
    pub fn list_for(&self, recipient: &[u8; 32]) -> Result<Vec<InboxEntry>> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| Error::Invariant("inbox mutex poisoned"))?;
        let mut stmt = conn
            .prepare(
                "SELECT \"to\", \"from\", nonce, wire, plaintext, received_at
                 FROM inbox WHERE \"to\" = ?1 ORDER BY received_at DESC",
            )
            .map_err(map_sqlite)?;
        let rows = stmt
            .query_map(params![&recipient[..]], |r| {
                let to_b: Vec<u8> = r.get(0)?;
                let from_b: Vec<u8> = r.get(1)?;
                let nonce: Vec<u8> = r.get(2)?;
                let wire: Vec<u8> = r.get(3)?;
                let plaintext: Vec<u8> = r.get(4)?;
                let received_at: i64 = r.get(5)?;
                Ok((to_b, from_b, nonce, wire, plaintext, received_at))
            })
            .map_err(map_sqlite)?;
        let mut out = Vec::new();
        for r in rows {
            let (to_b, from_b, nonce, wire, plaintext, received_at) = r.map_err(map_sqlite)?;
            if to_b.len() != 32 || from_b.len() != 32 {
                continue;
            }
            let mut to = [0u8; 32];
            to.copy_from_slice(&to_b);
            let mut from = [0u8; 32];
            from.copy_from_slice(&from_b);
            out.push(InboxEntry {
                to,
                from,
                nonce,
                wire_envelope: wire,
                plaintext,
                received_at: received_at as u64,
            });
        }
        Ok(out)
    }

    /// Total rows currently held. Mostly for tests / metrics.
    pub fn len(&self) -> Result<usize> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| Error::Invariant("inbox mutex poisoned"))?;
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM inbox", [], |r| r.get(0))
            .unwrap_or(0);
        Ok(n as usize)
    }

    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }

    /// Delete every row addressed to `recipient`. Useful for testing
    /// and for a future "clear history" user action.
    pub fn clear_for(&self, recipient: &[u8; 32]) -> Result<usize> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| Error::Invariant("inbox mutex poisoned"))?;
        let n = conn
            .execute(
                "DELETE FROM inbox WHERE \"to\" = ?1",
                params![&recipient[..]],
            )
            .map_err(map_sqlite)?;
        Ok(n)
    }
}

fn map_sqlite(e: rusqlite::Error) -> Error {
    Error::Sqlite(e.to_string())
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS inbox (
    "to"        BLOB NOT NULL,
    "from"      BLOB NOT NULL,
    nonce       BLOB NOT NULL,
    wire        BLOB NOT NULL,
    plaintext   BLOB NOT NULL,
    received_at INTEGER NOT NULL,
    PRIMARY KEY ("to", "from", nonce)
);
CREATE INDEX IF NOT EXISTS inbox_by_recipient_time
    ON inbox ("to", received_at DESC);
"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(to: u8, from: u8, nonce: u8, ts: u64) -> InboxEntry {
        InboxEntry {
            to: [to; 32],
            from: [from; 32],
            nonce: vec![nonce; 16],
            wire_envelope: vec![0xAB; 8],
            plaintext: vec![0xCD; 4],
            received_at: ts,
        }
    }

    #[test]
    fn insert_then_list_returns_in_time_desc() {
        let dir = tempfile::tempdir().unwrap();
        let s = InboxStore::open(dir.path()).unwrap();
        s.insert(&sample(1, 2, 1, 100));
        s.insert(&sample(1, 2, 2, 200));
        s.insert(&sample(1, 3, 3, 150));
        let listed = s.list_for(&[1u8; 32]).unwrap();
        assert_eq!(listed.len(), 3);
        assert_eq!(listed[0].received_at, 200);
        assert_eq!(listed[1].received_at, 150);
        assert_eq!(listed[2].received_at, 100);
    }

    #[test]
    fn insert_dedup_on_to_from_nonce() {
        let dir = tempfile::tempdir().unwrap();
        let s = InboxStore::open(dir.path()).unwrap();
        s.insert(&sample(1, 2, 9, 100));
        s.insert(&sample(1, 2, 9, 200)); // same key — ignored
        assert_eq!(s.len().unwrap(), 1);
    }

    #[test]
    fn list_for_unknown_recipient_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let s = InboxStore::open(dir.path()).unwrap();
        s.insert(&sample(1, 2, 1, 100));
        let listed = s.list_for(&[9u8; 32]).unwrap();
        assert!(listed.is_empty());
    }

    #[test]
    fn clear_for_removes_only_target() {
        let dir = tempfile::tempdir().unwrap();
        let s = InboxStore::open(dir.path()).unwrap();
        s.insert(&sample(1, 2, 1, 100));
        s.insert(&sample(1, 2, 2, 200));
        s.insert(&sample(7, 2, 3, 300));
        let removed = s.clear_for(&[1u8; 32]).unwrap();
        assert_eq!(removed, 2);
        assert_eq!(s.len().unwrap(), 1);
    }

    #[test]
    fn round_trip_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        {
            let s = InboxStore::open(dir.path()).unwrap();
            s.insert(&sample(1, 2, 1, 100));
        }
        let s = InboxStore::open(dir.path()).unwrap();
        let listed = s.list_for(&[1u8; 32]).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].received_at, 100);
    }
}
