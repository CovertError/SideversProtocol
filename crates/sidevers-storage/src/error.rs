//! Errors raised by the storage layer.

use thiserror::Error;

pub type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("join: {0}")]
    Join(#[from] tokio::task::JoinError),

    /// The bytes returned for a hash do not BLAKE3 to that hash (§5.4).
    #[error("hash mismatch: expected {expected}, got {got}")]
    HashMismatch { expected: String, got: String },

    #[error("requested range {start}..{end} exceeds object size {size}")]
    RangeOutOfBounds { start: u64, end: u64, size: u64 },

    #[error("core: {0}")]
    Core(#[from] sidevers_core::Error),

    #[error("invariant violated: {0}")]
    Invariant(&'static str),
}
