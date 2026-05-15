//! Error types for the protocol core.

use thiserror::Error;

pub type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Debug, Error)]
pub enum Error {
    /// CBOR encode failed (typically an I/O error against our internal writer).
    #[error("CBOR encode failed: {0}")]
    CborEncode(String),

    /// CBOR decode failed: malformed bytes, unexpected type, missing key, etc.
    #[error("CBOR decode failed: {0}")]
    CborDecode(String),

    /// The CBOR bytes are not in canonical (deterministic) form.
    /// Per spec §3.1, all on-wire messages must use RFC 8949 §4.2.1 encoding.
    #[error("CBOR not in canonical encoding: {0}")]
    CborNotCanonical(&'static str),

    /// Address (bech32m) decoding failed.
    #[error("address decode failed: {0}")]
    Address(String),

    /// Cryptographic signature did not verify.
    #[error("signature verification failed")]
    SignatureInvalid,

    /// Decryption failed: wrong key, tampered ciphertext, or wrong nonce.
    #[error("payload decryption failed")]
    DecryptionFailed,

    /// Envelope timestamp was outside the acceptable skew window (spec §3.2).
    #[error("envelope timestamp outside ±{max_skew_secs}s window")]
    TimestampSkewed { max_skew_secs: u64 },

    /// Replay detected: a (from, nonce) pair was observed within the window.
    #[error("replay detected")]
    Replay,

    /// Envelope protocol version is unknown or unsupported.
    #[error("unsupported protocol version: {got}")]
    UnsupportedVersion { got: u64 },

    /// Message type is in a reserved range that requires a type-unknown error.
    /// Per spec §3.5, range 0x70-0xEF is reserved for future minor versions and
    /// MUST trigger this response.
    #[error("unknown message type: 0x{0:02X}")]
    UnknownType(u8),

    /// The OS CSPRNG (`getrandom`) is unavailable. Per spec §2.3 we MUST refuse
    /// to generate keys on a platform without a working CSPRNG.
    #[error("OS CSPRNG unavailable: {0}")]
    CsprngUnavailable(String),

    /// A field bytestring had the wrong length for its declared type.
    #[error("field {field} expected {expected} bytes, got {got}")]
    BadFieldLength {
        field: &'static str,
        expected: usize,
        got: usize,
    },

    /// An invariant of the spec was violated by encoded data.
    #[error("protocol invariant violated: {0}")]
    Invariant(&'static str),
}
