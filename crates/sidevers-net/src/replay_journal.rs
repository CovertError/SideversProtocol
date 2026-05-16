//! Phase 1.E: durable replay-journal backed by SQLite.
//!
//! Implements [`sidevers_core::replay::ReplayJournal`] over a dedicated
//! `rusqlite::Connection`. One row per `(from, nonce)` pair currently in
//! the cache; the cache writes through on every insert and eviction.
//!
//! On node restart, [`SqliteReplayJournal::load_active`] reads the
//! journaled rows whose age is still under the cache TTL and returns
//! them to the caller, which preloads them into a fresh in-memory
//! `ReplayCache`. The result: the 600-second window survives a restart,
//! closing the §3.2 gap noted in the Phase-1 plan.
//!
//! Concurrency: the journal owns a *separate* SQLite connection from
//! `SideStore` (both files happen to live in the same `sides.db`, but
//! SQLite supports multiple connections to the same database). The
//! connection is wrapped in a `std::sync::Mutex` because the
//! `ReplayJournal` trait is sync — the cache calls these methods under
//! its own lock, so the journal latency directly serializes inbound
//! traffic. SQLite's write path here is microseconds for a 64-byte row,
//! which is well within budget.
//!
//! On any DB error we log + drop the change rather than propagating —
//! the in-memory cache is the source of truth at runtime; the journal
//! is a best-effort durability layer.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{Connection, params};
use sidevers_core::envelope::NONCE_LEN;
use sidevers_core::keys::PUBLIC_KEY_LEN;
use sidevers_core::replay::ReplayJournal;
use tracing::warn;

use crate::error::{Error, Result};

/// Tuple shape of one journaled replay entry, returned by
/// [`SqliteReplayJournal::load_active`]. `(from, nonce, first_seen)`.
pub type ReplayJournalEntry = ([u8; PUBLIC_KEY_LEN], [u8; NONCE_LEN], u64);

/// SQLite-backed write-through journal for the replay cache.
#[derive(Debug)]
pub struct SqliteReplayJournal {
    conn: Mutex<Connection>,
}

impl SqliteReplayJournal {
    /// Open (or create) the journal under `<data_dir>/sides.db` in its
    /// own dedicated table. The directory must already exist (the Node
    /// creates it during start).
    pub fn open(data_dir: &Path) -> Result<Self> {
        let path = data_dir.join("sides.db");
        let conn = Connection::open(&path).map_err(map_sqlite)?;
        // Phase 1.H3 (audit-pass): WAL + synchronous=NORMAL so the
        // hot-path `observe()` write doesn't fsync per envelope. The
        // journal is best-effort durability — losing the last few
        // writes on a crash is acceptable because the in-memory cache
        // remains authoritative at runtime.
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;\nPRAGMA synchronous=NORMAL;\nPRAGMA temp_store=MEMORY;",
        )
        .map_err(map_sqlite)?;
        conn.execute_batch(SCHEMA).map_err(map_sqlite)?;
        // Phase 1.H1 (audit-pass): owner-only file mode. The journal
        // itself isn't sensitive but it lives in the same `sides.db`
        // that holds raw side seeds.
        let _ = crate::fs_perms::lock_down_file(&path);
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Load journaled entries whose age `(now - first_seen)` is strictly
    /// less than `ttl_secs`. Older rows are deleted from the journal as
    /// a side effect — they would have been swept on first use anyway.
    pub fn load_active(&self, now_ts_secs: u64, ttl_secs: u64) -> Result<Vec<ReplayJournalEntry>> {
        let cutoff = now_ts_secs.saturating_sub(ttl_secs);
        // Mutex poisoning here would mean a panic inside a previous
        // journal call. Fall back to a best-effort empty load rather
        // than crashing the node on startup.
        let Ok(conn) = self.conn.lock() else {
            warn!("replay journal: mutex poisoned, returning empty preload");
            return Ok(Vec::new());
        };

        // 1. Drop stale rows.
        if let Err(e) = conn.execute(
            "DELETE FROM replay_journal WHERE first_seen < ?1",
            params![cutoff as i64],
        ) {
            warn!(error = %e, "replay journal: stale sweep failed");
        }

        // 2. Read fresh rows.
        let mut stmt = conn
            .prepare("SELECT \"from\", nonce, first_seen FROM replay_journal")
            .map_err(map_sqlite)?;
        let rows = stmt
            .query_map([], |r| {
                let from_bytes: Vec<u8> = r.get(0)?;
                let nonce_bytes: Vec<u8> = r.get(1)?;
                let first_seen: i64 = r.get(2)?;
                Ok((from_bytes, nonce_bytes, first_seen))
            })
            .map_err(map_sqlite)?;

        let mut out = Vec::new();
        for r in rows {
            let (from_bytes, nonce_bytes, first_seen) = r.map_err(map_sqlite)?;
            if from_bytes.len() != PUBLIC_KEY_LEN || nonce_bytes.len() != NONCE_LEN {
                // Don't trust malformed rows from a corrupted DB —
                // skip them silently so a single bad row can't block
                // boot.
                continue;
            }
            let mut from = [0u8; PUBLIC_KEY_LEN];
            from.copy_from_slice(&from_bytes);
            let mut nonce = [0u8; NONCE_LEN];
            nonce.copy_from_slice(&nonce_bytes);
            out.push((from, nonce, first_seen as u64));
        }
        Ok(out)
    }
}

fn map_sqlite(e: rusqlite::Error) -> Error {
    Error::Sqlite(e.to_string())
}

impl ReplayJournal for SqliteReplayJournal {
    fn record(&self, from: &[u8; PUBLIC_KEY_LEN], nonce: &[u8; NONCE_LEN], first_seen: u64) {
        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(_) => return,
        };
        let _ = conn
            .execute(
                "INSERT OR REPLACE INTO replay_journal (\"from\", nonce, first_seen) VALUES (?1, ?2, ?3)",
                params![&from[..], &nonce[..], first_seen as i64],
            )
            .inspect_err(|e| warn!(error = %e, "replay journal: record failed"));
    }

    fn evict(&self, from: &[u8; PUBLIC_KEY_LEN], nonce: &[u8; NONCE_LEN]) {
        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(_) => return,
        };
        let _ = conn
            .execute(
                "DELETE FROM replay_journal WHERE \"from\" = ?1 AND nonce = ?2",
                params![&from[..], &nonce[..]],
            )
            .inspect_err(|e| warn!(error = %e, "replay journal: evict failed"));
    }
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS replay_journal (
    "from"      BLOB NOT NULL,
    nonce       BLOB NOT NULL,
    first_seen  INTEGER NOT NULL,
    PRIMARY KEY ("from", nonce)
);
CREATE INDEX IF NOT EXISTS replay_journal_first_seen
    ON replay_journal (first_seen);
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn round_trip_record_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let j = SqliteReplayJournal::open(dir.path()).unwrap();
        let from = [1u8; PUBLIC_KEY_LEN];
        let nonce = [2u8; NONCE_LEN];
        j.record(&from, &nonce, 1000);
        let entries = j.load_active(1100, 600).unwrap();
        assert_eq!(entries, vec![(from, nonce, 1000)]);
    }

    #[test]
    fn stale_entries_dropped_at_load() {
        let dir = tempfile::tempdir().unwrap();
        let j = SqliteReplayJournal::open(dir.path()).unwrap();
        let from = [1u8; PUBLIC_KEY_LEN];
        let nonce = [2u8; NONCE_LEN];
        j.record(&from, &nonce, 1000);
        let entries = j.load_active(2000, 600).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn evict_removes_row() {
        let dir = tempfile::tempdir().unwrap();
        let j = SqliteReplayJournal::open(dir.path()).unwrap();
        let from = [1u8; PUBLIC_KEY_LEN];
        let nonce = [2u8; NONCE_LEN];
        j.record(&from, &nonce, 1000);
        j.evict(&from, &nonce);
        assert!(j.load_active(1050, 600).unwrap().is_empty());
    }

    #[test]
    fn cache_round_trip_through_journal_simulates_restart() {
        let dir = tempfile::tempdir().unwrap();
        let from = [3u8; PUBLIC_KEY_LEN];
        let nonce = [4u8; NONCE_LEN];

        // First "run": observe an envelope, journal records it.
        {
            let journal = Arc::new(SqliteReplayJournal::open(dir.path()).unwrap());
            let mut cache = sidevers_core::replay::ReplayCache::with_ttl(600);
            cache.set_journal(journal.clone());
            assert!(!cache.observe(1000, &from, &nonce));
        }

        // Second "run": new cache, preload from journal — replay must
        // still be detected.
        {
            let journal = Arc::new(SqliteReplayJournal::open(dir.path()).unwrap());
            let entries = journal.load_active(1100, 600).unwrap();
            let mut cache = sidevers_core::replay::ReplayCache::with_ttl(600);
            cache.preload(1100, entries);
            cache.set_journal(journal);
            assert!(
                cache.observe(1150, &from, &nonce),
                "replay must be detected after process restart"
            );
        }
    }
}
