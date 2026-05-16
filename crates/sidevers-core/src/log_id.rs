//! Log-safe identifier formatting.
//!
//! Side public keys and addresses are the on-wire identifier of a user, so
//! the protocol's unlinkability guarantee for anyone with log access depends
//! on never writing them out in full. `LogId` renders an arbitrary byte slice
//! as an 8-character hex prefix followed by `…`, suitable for log correlation
//! but not for re-identification. Use it anywhere a side, address, peer key,
//! or other user-identifying byte string would otherwise reach a `tracing`
//! event, log line, or `Debug` representation.
//!
//! ```
//! use sidevers_core::LogId;
//! let key = [0xa3, 0xf1, 0xc2, 0x99, 0x00, 0x11, 0x22, 0x33];
//! assert_eq!(format!("{}", LogId::new(&key)), "a3f1c299…");
//! assert_eq!(format!("{}", LogId::new(&[])), "");
//! ```
//!
//! In `tracing::instrument` macros use the `%` formatter:
//! `fields(peer = %LogId::new(&peer_side))`.

use core::fmt;

const PREFIX_BYTES: usize = 4;

#[derive(Clone, Copy)]
pub struct LogId<'a>(&'a [u8]);

impl<'a> LogId<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }
}

impl fmt::Display for LogId<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let n = core::cmp::min(self.0.len(), PREFIX_BYTES);
        for b in &self.0[..n] {
            write!(f, "{b:02x}")?;
        }
        if !self.0.is_empty() {
            write!(f, "…")?;
        }
        Ok(())
    }
}

impl fmt::Debug for LogId<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncates_to_prefix() {
        let key = [0xa3, 0xf1, 0xc2, 0x99, 0x00, 0x11, 0x22, 0x33];
        assert_eq!(format!("{}", LogId::new(&key)), "a3f1c299…");
    }

    #[test]
    fn empty_renders_empty() {
        assert_eq!(format!("{}", LogId::new(&[])), "");
    }

    #[test]
    fn shorter_than_prefix_pads_no_ellipsis_when_empty() {
        assert_eq!(format!("{}", LogId::new(&[0xab])), "ab…");
        assert_eq!(format!("{}", LogId::new(&[0xab, 0xcd])), "abcd…");
    }

    #[test]
    fn debug_matches_display() {
        let key = [0xa3, 0xf1, 0xc2, 0x99, 0x00];
        assert_eq!(format!("{:?}", LogId::new(&key)), "a3f1c299…");
    }

    #[test]
    fn never_emits_full_key_for_32_byte_input() {
        let key = [0xff_u8; 32];
        let s = format!("{}", LogId::new(&key));
        assert!(s.len() < 32, "must not render full key, got: {s}");
        assert!(s.ends_with('…'));
    }
}
