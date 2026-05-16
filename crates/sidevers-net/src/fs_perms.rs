//! Phase 1.H1 (audit-pass): owner-only filesystem permissions for
//! every store this crate creates.
//!
//! All four persistent stores (`SideStore`, `InboxStore`,
//! `SqliteReplayJournal`, `ObjectStore`) live under the operator-chosen
//! `data_dir`. By default each file is created with the process umask
//! (typically `022` on Unix → mode 644), which means **any local user
//! on a shared machine can read raw side seeds, plaintext inbox
//! contents, and content-addressed blobs**. Single-user desktops are
//! fine; multi-user Linux servers are exposed.
//!
//! This module provides two helpers:
//!
//!   * [`lock_down_file`] — chmod a file to `0o600` (owner read+write).
//!   * [`lock_down_dir`]  — chmod a directory to `0o700` (owner enter+list).
//!
//! Both are no-ops on non-Unix platforms; Windows ACLs work
//! differently and the rust standard library doesn't expose the
//! equivalent operations portably. Document the multi-user concern
//! for Windows operators separately.

use std::path::Path;

/// Restrict `path` to owner read+write (mode `0o600` on Unix). No-op
/// on Windows. Returns `Ok(())` on every platform even if the chmod
/// call fails — we don't want a permission-setting failure to block
/// the store from opening; we just lose the defense.
pub fn lock_down_file(path: &Path) -> std::io::Result<()> {
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

/// Restrict `path` to owner enter+list+write (mode `0o700` on Unix).
/// No-op on Windows.
pub fn lock_down_dir(path: &Path) -> std::io::Result<()> {
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

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn lock_down_file_sets_0o600() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("seed.bin");
        std::fs::write(&path, b"secret").unwrap();
        lock_down_file(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn lock_down_dir_sets_0o700() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("inner");
        std::fs::create_dir(&path).unwrap();
        lock_down_dir(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }
}
