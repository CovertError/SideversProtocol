//! SQLite schema + open/migrate logic for the object store.

use std::path::Path;

use rusqlite::Connection;

use crate::error::Result;

pub(crate) fn open_and_migrate(db_path: &Path) -> Result<Connection> {
    let conn = Connection::open(db_path)?;
    // WAL mode for concurrent readers + a single writer.
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    migrate(&conn)?;
    Ok(conn)
}

fn migrate(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS objects (
            hash         BLOB PRIMARY KEY NOT NULL CHECK (length(hash) = 32),
            size         INTEGER NOT NULL,
            mime         TEXT,
            inline       BLOB,
            pinned       INTEGER NOT NULL DEFAULT 0,
            added_at     INTEGER NOT NULL,
            last_accessed INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_objects_pinned ON objects(pinned);
        -- Phase 1.H2 (audit-pass): composite index for LRU eviction.
        -- `evict_to_budget` walks unpinned rows oldest-first; without
        -- this index the SELECT was a full table scan that stalled
        -- the conn lock for ~50ms+ at 100k objects.
        CREATE INDEX IF NOT EXISTS objects_evict
            ON objects (pinned, last_accessed ASC, added_at ASC);
        "#,
    )?;
    Ok(())
}
