//! Content-addressed object store (protocol spec §5).
//!
//! Each object's address is `BLAKE3(bytes)`. The store is split between a
//! SQLite metadata table and a blob filesystem under `<data_dir>/objects/`.
//! Small objects (`<= INLINE_MAX`) are stored inline in SQLite for fewer
//! filesystem entries; larger objects live as files at
//! `<data_dir>/objects/<hex[0:2]>/<hex>`.
//!
//! **Hash-on-fetch is mandatory** (§5.4): every read recomputes BLAKE3 over
//! the returned bytes before they leave this module. A tampered blob on
//! disk is rejected with `Error::HashMismatch` — the caller never sees the
//! bad bytes.

use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::params;
use tokio::sync::Mutex;

use crate::db;
use crate::error::{Error, Result};

/// Below this byte threshold, store objects inline in the SQLite table.
pub const INLINE_MAX: usize = 4096;

/// BLAKE3 address length, in bytes.
pub const ADDRESS_LEN: usize = 32;

/// Phase 1.C2 default disk budget for the object store. Eviction stays
/// idle until the total stored bytes exceed this. `0` (the default if
/// never explicitly set) disables eviction entirely — backward-compatible
/// with pre-1.C2 behavior.
pub const DEFAULT_MAX_BYTES: u64 = 0;

#[derive(Clone)]
pub struct ObjectStore {
    inner: Arc<Inner>,
}

struct Inner {
    conn: Mutex<rusqlite::Connection>,
    blob_dir: PathBuf,
    /// Phase 1.C2: soft disk-budget cap (bytes). `0` = no eviction.
    /// Atomic so callers can reconfigure live without taking the conn lock.
    max_bytes: AtomicU64,
}

impl ObjectStore {
    /// Open (or create) the store at `data_dir`. Creates the SQLite database
    /// and the blob filesystem subdirectory if missing.
    pub async fn open(data_dir: &Path) -> Result<Self> {
        let data_dir = data_dir.to_owned();
        tokio::task::spawn_blocking(move || -> Result<Self> {
            std::fs::create_dir_all(&data_dir)?;
            let blob_dir = data_dir.join("objects");
            std::fs::create_dir_all(&blob_dir)?;
            let db_path = data_dir.join("objects.db");
            let conn = db::open_and_migrate(&db_path)?;
            // Phase 1.H1 (audit-pass): lock down the SQLite metadata
            // file, the blob subtree, and the parent dir to owner-only
            // so other local users on shared machines can't read the
            // content-addressed cache.
            let _ = lock_down_dir_owner_only(&data_dir);
            let _ = lock_down_dir_owner_only(&blob_dir);
            let _ = lock_down_file_owner_only(&db_path);
            Ok(Self {
                inner: Arc::new(Inner {
                    conn: Mutex::new(conn),
                    blob_dir,
                    max_bytes: AtomicU64::new(DEFAULT_MAX_BYTES),
                }),
            })
        })
        .await?
    }

    /// Phase 1.C2: set the soft disk budget (bytes). When the on-disk +
    /// inline total exceeds this, [`Self::evict_to_budget`] removes the
    /// least-recently-accessed unpinned objects until the total fits.
    /// `0` disables eviction (backward-compatible default).
    pub fn set_max_bytes(&self, max_bytes: u64) {
        self.inner.max_bytes.store(max_bytes, Ordering::Relaxed);
    }

    pub fn max_bytes(&self) -> u64 {
        self.inner.max_bytes.load(Ordering::Relaxed)
    }

    /// Total bytes recorded across all objects (sum of `size` column).
    pub async fn total_bytes(&self) -> Result<u64> {
        let conn = self.inner.conn.lock().await;
        let total: i64 = conn
            .query_row("SELECT COALESCE(SUM(size), 0) FROM objects", [], |r| {
                r.get(0)
            })
            .unwrap_or(0);
        Ok(total as u64)
    }

    /// Phase 1.C2: LRU eviction of unpinned objects until total bytes
    /// fits the configured budget. Returns the count + bytes evicted.
    /// No-ops if `max_bytes == 0`. Pinned objects are never evicted.
    pub async fn evict_to_budget(&self) -> Result<(usize, u64)> {
        let budget = self.inner.max_bytes.load(Ordering::Relaxed);
        if budget == 0 {
            return Ok((0, 0));
        }
        let total = self.total_bytes().await?;
        if total <= budget {
            return Ok((0, 0));
        }
        // Collect candidates (unpinned), oldest-first.
        let candidates: Vec<([u8; ADDRESS_LEN], u64)> = {
            let conn = self.inner.conn.lock().await;
            let mut stmt = conn.prepare(
                "SELECT hash, size FROM objects WHERE pinned = 0 \
                 ORDER BY last_accessed ASC, added_at ASC",
            )?;
            let rows = stmt.query_map([], |r| {
                let h: Vec<u8> = r.get(0)?;
                let sz: i64 = r.get(1)?;
                Ok((h, sz as u64))
            })?;
            let mut out = Vec::new();
            for r in rows {
                let (h_bytes, sz) = r?;
                if h_bytes.len() != ADDRESS_LEN {
                    continue;
                }
                let mut arr = [0u8; ADDRESS_LEN];
                arr.copy_from_slice(&h_bytes);
                out.push((arr, sz));
            }
            out
        };

        let mut bytes_to_drop = total.saturating_sub(budget);
        let mut count = 0usize;
        let mut bytes = 0u64;
        for (hash, size) in candidates {
            if bytes_to_drop == 0 {
                break;
            }
            self.evict_one(&hash).await?;
            count += 1;
            bytes += size;
            bytes_to_drop = bytes_to_drop.saturating_sub(size);
        }
        Ok((count, bytes))
    }

    /// Drop a single object's bytes (file + row). Idempotent. Used by
    /// `evict_to_budget`; also useful for `STORAGE_RETRACT` once the
    /// last publisher releases provenance.
    pub async fn evict_one(&self, hash: &[u8; ADDRESS_LEN]) -> Result<()> {
        // Best-effort: delete file (ignore not-found), then drop the row.
        let path = blob_path(&self.inner.blob_dir, hash);
        if path.exists() {
            tokio::fs::remove_file(&path).await.ok();
        }
        let conn = self.inner.conn.lock().await;
        conn.execute("DELETE FROM objects WHERE hash = ?", params![&hash[..]])?;
        Ok(())
    }

    /// Store `bytes`. Returns the BLAKE3 address.
    pub async fn put(&self, bytes: Vec<u8>) -> Result<[u8; ADDRESS_LEN]> {
        let hash = blake3::hash(&bytes);
        let hash_arr: [u8; ADDRESS_LEN] = *hash.as_bytes();
        let size = bytes.len() as u64;
        let inline = bytes.len() <= INLINE_MAX;
        let now = unix_now();

        let inner = self.inner.clone();
        if inline {
            let conn = inner.conn.lock().await;
            conn.execute(
                "INSERT OR IGNORE INTO objects(hash, size, mime, inline, pinned, added_at, last_accessed) \
                 VALUES (?, ?, NULL, ?, 0, ?, ?)",
                params![&hash_arr[..], size as i64, &bytes[..], now as i64, now as i64],
            )?;
        } else {
            // Write the blob first, then index it; SQL "INSERT OR IGNORE" makes
            // re-inserts idempotent (content-addressed: same bytes → same hash).
            let path = blob_path(&inner.blob_dir, &hash_arr);
            if let Some(parent) = path.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            tokio::fs::write(&path, &bytes).await?;
            let conn = inner.conn.lock().await;
            conn.execute(
                "INSERT OR IGNORE INTO objects(hash, size, mime, inline, pinned, added_at, last_accessed) \
                 VALUES (?, ?, NULL, NULL, 0, ?, ?)",
                params![&hash_arr[..], size as i64, now as i64, now as i64],
            )?;
        }
        Ok(hash_arr)
    }

    /// Check whether an object exists in the store.
    pub async fn has(&self, hash: &[u8; ADDRESS_LEN]) -> Result<bool> {
        let conn = self.inner.conn.lock().await;
        let mut stmt = conn.prepare("SELECT 1 FROM objects WHERE hash = ?")?;
        let mut rows = stmt.query(params![&hash[..]])?;
        Ok(rows.next()?.is_some())
    }

    /// Object size, if present.
    pub async fn size(&self, hash: &[u8; ADDRESS_LEN]) -> Result<Option<u64>> {
        let conn = self.inner.conn.lock().await;
        let mut stmt = conn.prepare("SELECT size FROM objects WHERE hash = ?")?;
        let row: Option<i64> = stmt.query_row(params![&hash[..]], |r| r.get(0)).ok();
        Ok(row.map(|s| s as u64))
    }

    /// Fetch a whole object. Returns `None` if not present. Always
    /// hash-verifies before returning bytes (§5.4).
    pub async fn get(&self, hash: &[u8; ADDRESS_LEN]) -> Result<Option<Vec<u8>>> {
        // Load metadata + inline (if any).
        let (inline_bytes, on_disk) = {
            let conn = self.inner.conn.lock().await;
            let mut stmt = conn.prepare("SELECT inline FROM objects WHERE hash = ?")?;
            let row: Option<Option<Vec<u8>>> =
                stmt.query_row(params![&hash[..]], |r| r.get(0)).ok();
            match row {
                None => return Ok(None),
                Some(Some(bytes)) => (Some(bytes), false),
                Some(None) => (None, true),
            }
        };
        let bytes = if let Some(b) = inline_bytes {
            b
        } else if on_disk {
            let path = blob_path(&self.inner.blob_dir, hash);
            tokio::fs::read(&path).await?
        } else {
            return Err(Error::Invariant(
                "object row has neither inline blob nor disk file",
            ));
        };
        verify_hash(&bytes, hash)?;
        touch_last_accessed(&self.inner.conn, hash).await?;
        Ok(Some(bytes))
    }

    /// Fetch a byte range of an object. Range is exclusive on the upper end:
    /// `start..end` returns `bytes[start..end]`. Hash-verifies the **whole
    /// object** first, then slices — there's no way to verify a range without
    /// the whole BLAKE3 digest.
    pub async fn get_range(
        &self,
        hash: &[u8; ADDRESS_LEN],
        range: Range<u64>,
    ) -> Result<Option<Vec<u8>>> {
        let whole = match self.get(hash).await? {
            Some(b) => b,
            None => return Ok(None),
        };
        let size = whole.len() as u64;
        if range.start > range.end || range.end > size {
            return Err(Error::RangeOutOfBounds {
                start: range.start,
                end: range.end,
                size,
            });
        }
        Ok(Some(
            whole[(range.start as usize)..(range.end as usize)].to_vec(),
        ))
    }

    /// Mark an object as pinned (don't evict; informational in v1).
    pub async fn pin(&self, hash: &[u8; ADDRESS_LEN]) -> Result<()> {
        let conn = self.inner.conn.lock().await;
        conn.execute(
            "UPDATE objects SET pinned = 1 WHERE hash = ?",
            params![&hash[..]],
        )?;
        Ok(())
    }

    pub async fn unpin(&self, hash: &[u8; ADDRESS_LEN]) -> Result<()> {
        let conn = self.inner.conn.lock().await;
        conn.execute(
            "UPDATE objects SET pinned = 0 WHERE hash = ?",
            params![&hash[..]],
        )?;
        Ok(())
    }
}

fn blob_path(blob_dir: &Path, hash: &[u8; ADDRESS_LEN]) -> PathBuf {
    let hex = hex::encode(hash);
    blob_dir.join(&hex[..2]).join(hex)
}

/// Phase 1.H1 (audit-pass): chmod 0o600 the file (owner read+write).
/// No-op on non-Unix.
fn lock_down_file_owner_only(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path)?;
        let mut perms = meta.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms)?;
    }
    let _ = path;
    Ok(())
}

/// Phase 1.H1 (audit-pass): chmod 0o700 the directory (owner-only).
fn lock_down_dir_owner_only(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path)?;
        let mut perms = meta.permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(path, perms)?;
    }
    let _ = path;
    Ok(())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn verify_hash(bytes: &[u8], expected: &[u8; ADDRESS_LEN]) -> Result<()> {
    use subtle::ConstantTimeEq;
    let got = blake3::hash(bytes);
    // Constant-time compare (Audit P2.D). Not exploitable for confidentiality
    // — the hash is over content the requester already knows — but auditors
    // expect every hash compare in a crypto library to be constant-time, and
    // a future use of `verify_hash` in an authentication context would
    // otherwise be a footgun.
    if bool::from(got.as_bytes().ct_eq(expected)) {
        Ok(())
    } else {
        Err(Error::HashMismatch {
            expected: hex::encode(expected),
            got: hex::encode(got.as_bytes()),
        })
    }
}

async fn touch_last_accessed(
    conn: &Mutex<rusqlite::Connection>,
    hash: &[u8; ADDRESS_LEN],
) -> Result<()> {
    let now = unix_now() as i64;
    let conn = conn.lock().await;
    conn.execute(
        "UPDATE objects SET last_accessed = ? WHERE hash = ?",
        params![now, &hash[..]],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn put_then_get_round_trip_small() {
        let tmp = TempDir::new().unwrap();
        let store = ObjectStore::open(tmp.path()).await.unwrap();
        let hash = store.put(b"hello sidevers".to_vec()).await.unwrap();
        let got = store.get(&hash).await.unwrap().unwrap();
        assert_eq!(got, b"hello sidevers");
        assert!(store.has(&hash).await.unwrap());
        assert_eq!(store.size(&hash).await.unwrap(), Some(14));
    }

    #[tokio::test]
    async fn put_then_get_round_trip_large_blob() {
        let tmp = TempDir::new().unwrap();
        let store = ObjectStore::open(tmp.path()).await.unwrap();
        let big = vec![0xAB; INLINE_MAX * 4]; // 16 KiB → out-of-line
        let hash = store.put(big.clone()).await.unwrap();
        let got = store.get(&hash).await.unwrap().unwrap();
        assert_eq!(got, big);
        // The blob path exists on disk.
        let path = blob_path(&tmp.path().join("objects"), &hash);
        assert!(path.exists());
    }

    #[tokio::test]
    async fn unknown_hash_returns_none() {
        let tmp = TempDir::new().unwrap();
        let store = ObjectStore::open(tmp.path()).await.unwrap();
        let h = [0u8; ADDRESS_LEN];
        assert!(store.get(&h).await.unwrap().is_none());
        assert!(!store.has(&h).await.unwrap());
    }

    #[tokio::test]
    async fn tampered_disk_blob_is_rejected() {
        let tmp = TempDir::new().unwrap();
        let store = ObjectStore::open(tmp.path()).await.unwrap();
        let big = vec![0x77; INLINE_MAX * 4];
        let hash = store.put(big).await.unwrap();

        // Tamper with the file on disk.
        let path = blob_path(&tmp.path().join("objects"), &hash);
        let mut bad = std::fs::read(&path).unwrap();
        bad[0] ^= 0x01;
        std::fs::write(&path, &bad).unwrap();

        // get must reject the tampered bytes — the caller never sees them.
        let err = store.get(&hash).await.unwrap_err();
        assert!(matches!(err, Error::HashMismatch { .. }), "got {err:?}");
    }

    #[tokio::test]
    async fn range_fetch_works_and_hash_verifies() {
        let tmp = TempDir::new().unwrap();
        let store = ObjectStore::open(tmp.path()).await.unwrap();
        let bytes: Vec<u8> = (0..50u8).collect();
        let hash = store.put(bytes.clone()).await.unwrap();
        let mid = store.get_range(&hash, 10..20).await.unwrap().unwrap();
        assert_eq!(mid, bytes[10..20]);
    }

    #[tokio::test]
    async fn evict_to_budget_no_op_when_under_budget() {
        let tmp = TempDir::new().unwrap();
        let store = ObjectStore::open(tmp.path()).await.unwrap();
        store.set_max_bytes(1024 * 1024);
        store.put(b"small".to_vec()).await.unwrap();
        let (count, bytes) = store.evict_to_budget().await.unwrap();
        assert_eq!(count, 0);
        assert_eq!(bytes, 0);
    }

    #[tokio::test]
    async fn evict_to_budget_drops_oldest_unpinned_until_under_budget() {
        let tmp = TempDir::new().unwrap();
        let store = ObjectStore::open(tmp.path()).await.unwrap();
        // Use small budget that fits 1.5 inline objects.
        // Three 100-byte objects, budget 150 bytes → must drop two.
        let h1 = store.put(vec![0xAA; 100]).await.unwrap();
        // Force monotonic last_accessed by touching h1 explicitly later;
        // for now insert h2, h3 in order so their added_at orders too.
        let h2 = store.put(vec![0xBB; 100]).await.unwrap();
        let h3 = store.put(vec![0xCC; 100]).await.unwrap();
        store.set_max_bytes(150);
        let (count, bytes) = store.evict_to_budget().await.unwrap();
        assert!(
            count >= 2 && bytes >= 200,
            "expected to drop at least 2 objects (>=200 bytes), got count={count} bytes={bytes}"
        );
        // h3 (newest) should still be there.
        assert!(store.has(&h3).await.unwrap());
        // At least one of h1/h2 (oldest) must have been removed.
        assert!(!store.has(&h1).await.unwrap() || !store.has(&h2).await.unwrap());
    }

    #[tokio::test]
    async fn evict_to_budget_skips_pinned() {
        let tmp = TempDir::new().unwrap();
        let store = ObjectStore::open(tmp.path()).await.unwrap();
        let h1 = store.put(vec![0xAA; 100]).await.unwrap();
        let h2 = store.put(vec![0xBB; 100]).await.unwrap();
        store.pin(&h1).await.unwrap();
        store.set_max_bytes(50); // way under
        let _ = store.evict_to_budget().await.unwrap();
        // Pinned must survive.
        assert!(store.has(&h1).await.unwrap());
        // Unpinned must be gone.
        assert!(!store.has(&h2).await.unwrap());
    }

    #[tokio::test]
    async fn evict_to_budget_zero_budget_disables() {
        let tmp = TempDir::new().unwrap();
        let store = ObjectStore::open(tmp.path()).await.unwrap();
        let h = store.put(vec![0xAA; 100]).await.unwrap();
        // Default: max_bytes = 0 → eviction disabled even when "over."
        let (count, bytes) = store.evict_to_budget().await.unwrap();
        assert_eq!(count, 0);
        assert_eq!(bytes, 0);
        assert!(store.has(&h).await.unwrap());
    }

    #[tokio::test]
    async fn idempotent_double_put() {
        let tmp = TempDir::new().unwrap();
        let store = ObjectStore::open(tmp.path()).await.unwrap();
        let h1 = store.put(b"x".to_vec()).await.unwrap();
        let h2 = store.put(b"x".to_vec()).await.unwrap();
        assert_eq!(h1, h2);
        assert_eq!(store.size(&h1).await.unwrap(), Some(1));
    }
}
