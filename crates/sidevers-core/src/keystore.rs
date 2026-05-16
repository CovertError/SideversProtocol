//! Passphrase-sealed master seed (Audit P1.1).
//!
//! Sidevers identities are 32-byte Ed25519 seeds. Storing them in
//! plaintext on disk means stolen device = total identity compromise,
//! and is the single biggest gap in the "privacy-first" claim. This
//! module provides a self-describing CBOR-framed sealed-seed format
//! that wraps the raw seed under a user-chosen passphrase via
//! Argon2id (KDF) + ChaCha20-Poly1305 (AEAD).
//!
//! # Format (v1, canonical CBOR map, all keys present in order)
//!
//! ```text
//! {
//!   "version":     1,                     // format version (u64)
//!   "kdf":         "argon2id",            // KDF identifier
//!   "argon2_m":    19456,                 // memory cost in KiB
//!   "argon2_t":    2,                     // time cost (iterations)
//!   "argon2_p":    1,                     // parallelism
//!   "salt":        bstr(16),              // KDF salt, random per seal
//!   "aead":        "chacha20-poly1305",   // AEAD identifier
//!   "nonce":       bstr(12),              // AEAD nonce, random per seal
//!   "ct":          bstr(48),              // seed (32) ‖ tag (16)
//! }
//! ```
//!
//! The format version, KDF/AEAD identifiers, all Argon2 parameters, and
//! the salt are bound into the AEAD AAD, so a downgrade or parameter
//! swap (e.g. lowering memory cost on the wire to enable cheaper
//! offline guessing) is detected on open.
//!
//! # Parameter choice
//!
//! Defaults follow OWASP 2023 (Argon2id): `m = 19 MiB, t = 2, p = 1`.
//! These are tuned for modern desktops + mobile and intentionally fast
//! enough to not be user-hostile while expensive enough to make
//! brute-forcing meaningful passphrases costly. Callers may pass
//! custom `Argon2Params` (e.g. weaker for tests, stronger for
//! offline-archive backups).
//!
//! # What this module does NOT do
//!
//! * It does not enforce passphrase strength. Caller's responsibility.
//! * It does not encrypt the SQLite stores (planned follow-up).
//! * It does not interface with the OS keychain (planned follow-up).
//!
//! # Security properties
//!
//! * Wrong passphrase → AEAD open fails → `Error::DecryptionFailed`.
//! * Tampered ciphertext, salt, nonce, or any parameter → AEAD open
//!   fails (AAD binding).
//! * The plaintext is not retained anywhere in this module after
//!   `seal_seed` returns; the caller owns the cleartext seed.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use zeroize::Zeroize;

use crate::cbor::{self, CborReader, CborWriter, MapEntry};
use crate::error::{Error, Result};
use crate::keys::SECRET_KEY_LEN;

/// Current sealed-seed format version.
pub const SEALED_SEED_VERSION: u64 = 1;

const KDF_ARGON2ID: &str = "argon2id";
const AEAD_CC20P: &str = "chacha20-poly1305";

/// KDF salt length in bytes.
pub const SALT_LEN: usize = 16;

/// AEAD nonce length in bytes.
pub const AEAD_NONCE_LEN: usize = 12;

/// AEAD authentication tag length (Poly1305).
pub const AEAD_TAG_LEN: usize = 16;

/// Argon2id parameters used when sealing a seed.
///
/// Defaults follow OWASP 2023 guidance and are appropriate for desktop
/// and mobile clients. Custom params let tests run faster and let
/// offline-archive backups use stronger settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Params {
    /// Memory cost in KiB.
    pub m_kib: u32,
    /// Time cost (iterations).
    pub t: u32,
    /// Parallelism (lanes).
    pub p: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            m_kib: 19_456,
            t: 2,
            p: 1,
        }
    }
}

impl Argon2Params {
    /// Fast params for unit tests. **DO NOT** ship — these are
    /// brute-forceable in milliseconds.
    pub fn fast_for_tests() -> Self {
        Self {
            m_kib: 32,
            t: 1,
            p: 1,
        }
    }
}

/// Seal a master seed under a passphrase with default Argon2id params.
pub fn seal_seed(seed: &[u8; SECRET_KEY_LEN], passphrase: &str) -> Result<Vec<u8>> {
    seal_seed_with(seed, passphrase, &Argon2Params::default())
}

/// Seal a master seed under a passphrase with explicit Argon2id params.
pub fn seal_seed_with(
    seed: &[u8; SECRET_KEY_LEN],
    passphrase: &str,
    params: &Argon2Params,
) -> Result<Vec<u8>> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; AEAD_NONCE_LEN];
    getrandom::getrandom(&mut salt).map_err(|e| Error::CsprngUnavailable(e.to_string()))?;
    getrandom::getrandom(&mut nonce).map_err(|e| Error::CsprngUnavailable(e.to_string()))?;

    let mut kek = derive_kek(passphrase, &salt, params)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&kek));
    let aad = build_aad(SEALED_SEED_VERSION, KDF_ARGON2ID, AEAD_CC20P, params, &salt);
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &seed[..],
                aad: &aad,
            },
        )
        .map_err(|_| Error::Invariant("AEAD seal failed (impossible at fixed input length)"))?;
    kek.zeroize();

    Ok(encode_sealed(
        SEALED_SEED_VERSION,
        KDF_ARGON2ID,
        params,
        &salt,
        AEAD_CC20P,
        &nonce,
        &ct,
    ))
}

/// Open a sealed seed with a passphrase. Wrong passphrase, tampered
/// ciphertext, swapped AEAD nonce, or any modified parameter all
/// produce `Error::DecryptionFailed`.
pub fn open_seed(sealed: &[u8], passphrase: &str) -> Result<[u8; SECRET_KEY_LEN]> {
    let parsed = decode_sealed(sealed)?;
    if parsed.version != SEALED_SEED_VERSION {
        return Err(Error::CborDecode(format!(
            "sealed-seed format version {} not supported (this build knows v{})",
            parsed.version, SEALED_SEED_VERSION
        )));
    }
    if parsed.kdf != KDF_ARGON2ID {
        return Err(Error::CborDecode(format!(
            "sealed-seed kdf {:?} not supported",
            parsed.kdf
        )));
    }
    if parsed.aead != AEAD_CC20P {
        return Err(Error::CborDecode(format!(
            "sealed-seed aead {:?} not supported",
            parsed.aead
        )));
    }
    if parsed.salt.len() != SALT_LEN {
        return Err(Error::BadFieldLength {
            field: "salt",
            expected: SALT_LEN,
            got: parsed.salt.len(),
        });
    }
    if parsed.nonce.len() != AEAD_NONCE_LEN {
        return Err(Error::BadFieldLength {
            field: "nonce",
            expected: AEAD_NONCE_LEN,
            got: parsed.nonce.len(),
        });
    }
    let params = Argon2Params {
        m_kib: parsed.m_kib,
        t: parsed.t,
        p: parsed.p,
    };
    let mut kek = derive_kek(passphrase, &parsed.salt, &params)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&kek));
    let aad = build_aad(
        parsed.version,
        &parsed.kdf,
        &parsed.aead,
        &params,
        &parsed.salt,
    );
    let pt = cipher
        .decrypt(
            Nonce::from_slice(&parsed.nonce),
            Payload {
                msg: &parsed.ct,
                aad: &aad,
            },
        )
        .map_err(|_| Error::DecryptionFailed)?;
    kek.zeroize();

    if pt.len() != SECRET_KEY_LEN {
        return Err(Error::BadFieldLength {
            field: "seed",
            expected: SECRET_KEY_LEN,
            got: pt.len(),
        });
    }
    let mut out = [0u8; SECRET_KEY_LEN];
    out.copy_from_slice(&pt);
    Ok(out)
}

fn derive_kek(passphrase: &str, salt: &[u8], params: &Argon2Params) -> Result<[u8; 32]> {
    let argon2_params = Params::new(params.m_kib, params.t, params.p, Some(32))
        .map_err(|_| Error::Invariant("invalid Argon2 parameters"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);
    let mut kek = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut kek)
        .map_err(|_| Error::Invariant("Argon2 derivation failed"))?;
    Ok(kek)
}

/// Build the AEAD AAD — every format parameter that an attacker might
/// otherwise tamper with to weaken the seal must be authenticated.
fn build_aad(
    version: u64,
    kdf: &str,
    aead: &str,
    params: &Argon2Params,
    salt: &[u8],
) -> Vec<u8> {
    let mut w = CborWriter::new();
    w.write_array_header(7);
    w.write_u64(version);
    w.write_text(kdf);
    w.write_u64(params.m_kib as u64);
    w.write_u64(params.t as u64);
    w.write_u64(params.p as u64);
    w.write_text(aead);
    w.write_bytes(salt);
    w.into_bytes()
}

struct ParsedSealed {
    version: u64,
    kdf: String,
    m_kib: u32,
    t: u32,
    p: u32,
    salt: Vec<u8>,
    aead: String,
    nonce: Vec<u8>,
    ct: Vec<u8>,
}

fn encode_sealed(
    version: u64,
    kdf: &str,
    params: &Argon2Params,
    salt: &[u8],
    aead: &str,
    nonce: &[u8],
    ct: &[u8],
) -> Vec<u8> {
    // Canonical CBOR map order (RFC 8949 §4.2.1): keys sorted by the
    // bytewise lex order of their encoded form, which for text strings
    // means shorter keys first (smaller head byte), then lex within
    // each length:
    //   ct, kdf, aead, salt, nonce, version, argon2_m, argon2_p, argon2_t
    let entries = [
        MapEntry {
            key: cbor::text("ct"),
            value: cbor::bytes(ct),
        },
        MapEntry {
            key: cbor::text("kdf"),
            value: cbor::text(kdf),
        },
        MapEntry {
            key: cbor::text("aead"),
            value: cbor::text(aead),
        },
        MapEntry {
            key: cbor::text("salt"),
            value: cbor::bytes(salt),
        },
        MapEntry {
            key: cbor::text("nonce"),
            value: cbor::bytes(nonce),
        },
        MapEntry {
            key: cbor::text("version"),
            value: cbor::uint(version),
        },
        MapEntry {
            key: cbor::text("argon2_m"),
            value: cbor::uint(params.m_kib as u64),
        },
        MapEntry {
            key: cbor::text("argon2_p"),
            value: cbor::uint(params.p as u64),
        },
        MapEntry {
            key: cbor::text("argon2_t"),
            value: cbor::uint(params.t as u64),
        },
    ];
    cbor::encode_map(&entries)
}

fn decode_sealed(bytes: &[u8]) -> Result<ParsedSealed> {
    let mut r = CborReader::new(bytes);
    let n = r.read_map_header()?;
    if n != 9 {
        return Err(Error::CborDecode(format!(
            "sealed-seed expected 9 keys, got {n}"
        )));
    }
    // Canonical CBOR order: shorter first, then lex within length.
    let expected_keys = [
        "ct", "kdf", "aead", "salt", "nonce", "version", "argon2_m", "argon2_p", "argon2_t",
    ];
    let mut aead = None;
    let mut m_kib = None;
    let mut p = None;
    let mut t = None;
    let mut ct = None;
    let mut kdf = None;
    let mut nonce = None;
    let mut salt = None;
    let mut version = None;
    for ek in expected_keys {
        let k = r.read_text()?;
        if k != ek {
            return Err(Error::CborNotCanonical(
                "sealed-seed keys not in canonical order",
            ));
        }
        match ek {
            "aead" => aead = Some(r.read_text()?.to_owned()),
            "argon2_m" => m_kib = Some(u32_from_u64(r.read_u64()?, "argon2_m")?),
            "argon2_p" => p = Some(u32_from_u64(r.read_u64()?, "argon2_p")?),
            "argon2_t" => t = Some(u32_from_u64(r.read_u64()?, "argon2_t")?),
            "ct" => ct = Some(r.read_bytes()?.to_vec()),
            "kdf" => kdf = Some(r.read_text()?.to_owned()),
            "nonce" => nonce = Some(r.read_bytes()?.to_vec()),
            "salt" => salt = Some(r.read_bytes()?.to_vec()),
            "version" => version = Some(r.read_u64()?),
            _ => unreachable!(),
        }
    }
    if !r.at_end() {
        return Err(Error::CborDecode("trailing bytes after sealed-seed".into()));
    }
    Ok(ParsedSealed {
        version: version.ok_or(Error::Invariant("missing version"))?,
        kdf: kdf.ok_or(Error::Invariant("missing kdf"))?,
        m_kib: m_kib.ok_or(Error::Invariant("missing argon2_m"))?,
        t: t.ok_or(Error::Invariant("missing argon2_t"))?,
        p: p.ok_or(Error::Invariant("missing argon2_p"))?,
        salt: salt.ok_or(Error::Invariant("missing salt"))?,
        aead: aead.ok_or(Error::Invariant("missing aead"))?,
        nonce: nonce.ok_or(Error::Invariant("missing nonce"))?,
        ct: ct.ok_or(Error::Invariant("missing ct"))?,
    })
}

fn u32_from_u64(v: u64, name: &'static str) -> Result<u32> {
    u32::try_from(v).map_err(|_| Error::BadFieldLength {
        field: name,
        expected: 4,
        got: 8,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast() -> Argon2Params {
        Argon2Params::fast_for_tests()
    }

    #[test]
    fn round_trip_seed_through_passphrase_seal() {
        let seed = [0xABu8; SECRET_KEY_LEN];
        let sealed = seal_seed_with(&seed, "correct horse battery staple", &fast()).unwrap();
        let opened = open_seed(&sealed, "correct horse battery staple").unwrap();
        assert_eq!(seed, opened);
    }

    #[test]
    fn wrong_passphrase_fails_to_open() {
        let seed = [0x01u8; SECRET_KEY_LEN];
        let sealed = seal_seed_with(&seed, "right one", &fast()).unwrap();
        let err = open_seed(&sealed, "wrong one").unwrap_err();
        assert!(matches!(err, Error::DecryptionFailed), "got {err:?}");
    }

    #[test]
    fn each_seal_is_unique_because_salt_and_nonce_are_random() {
        let seed = [0x02u8; SECRET_KEY_LEN];
        let s1 = seal_seed_with(&seed, "p", &fast()).unwrap();
        let s2 = seal_seed_with(&seed, "p", &fast()).unwrap();
        assert_ne!(s1, s2, "two seals of the same seed must differ (random salt+nonce)");
        // Both should still open.
        assert_eq!(open_seed(&s1, "p").unwrap(), seed);
        assert_eq!(open_seed(&s2, "p").unwrap(), seed);
    }

    #[test]
    fn tampered_ciphertext_fails_to_open() {
        let seed = [0x03u8; SECRET_KEY_LEN];
        let mut sealed = seal_seed_with(&seed, "p", &fast()).unwrap();
        // Flip a bit somewhere near the end (likely in `ct`).
        let last = sealed.len() - 5;
        sealed[last] ^= 0x01;
        let err = open_seed(&sealed, "p").unwrap_err();
        // Could be DecryptionFailed (tag mismatch) or CborDecode (if we hit
        // structural bytes); both are acceptable rejection paths.
        assert!(
            matches!(err, Error::DecryptionFailed | Error::CborDecode(_) | Error::CborNotCanonical(_) | Error::BadFieldLength { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn tampered_salt_in_aad_fails_to_open() {
        // The AAD binds the salt; modifying the encoded salt MUST cause
        // open to fail even if the attacker also recomputes the KEK
        // from the new salt (they can't, without the passphrase).
        let seed = [0x04u8; SECRET_KEY_LEN];
        let mut sealed = seal_seed_with(&seed, "pw", &fast()).unwrap();
        // Find the salt bytes — they're prefixed by the salt-key bytes
        // `cbor::text("salt")` = [0x64, 's','a','l','t']. The next byte
        // is the bstr header for a 16-byte string: 0x50.
        let needle = b"salt";
        let pos = sealed.windows(4).position(|w| w == needle).expect("salt key present");
        // header byte at pos+4 should be 0x50 (bstr(16)); flip first salt byte.
        assert_eq!(sealed[pos + 4], 0x50);
        sealed[pos + 5] ^= 0xFF;
        let err = open_seed(&sealed, "pw").unwrap_err();
        assert!(matches!(err, Error::DecryptionFailed), "got {err:?}");
    }

    #[test]
    fn empty_passphrase_round_trip_still_works() {
        // Not recommended but should not crash.
        let seed = [0x05u8; SECRET_KEY_LEN];
        let sealed = seal_seed_with(&seed, "", &fast()).unwrap();
        let opened = open_seed(&sealed, "").unwrap();
        assert_eq!(seed, opened);
    }

    #[test]
    fn version_mismatch_is_reported() {
        let seed = [0x06u8; SECRET_KEY_LEN];
        let mut sealed = seal_seed_with(&seed, "p", &fast()).unwrap();
        // Find the "version" key and overwrite its value (a single u8
        // here because v=1 fits in head byte). The bytes around it:
        // ...text("version")=[0x67,'v','e','r','s','i','o','n'], then 0x01.
        let needle = b"version";
        let pos = sealed.windows(7).position(|w| w == needle).expect("version key present");
        let value_byte_idx = pos + 7;
        // Current v=1 encoded as 0x01 (head byte uint, info=1).
        assert_eq!(sealed[value_byte_idx], 0x01);
        // Bump to v=2 via head-byte uint info=2 (still canonical for small uints).
        sealed[value_byte_idx] = 0x02;
        let err = open_seed(&sealed, "p").unwrap_err();
        assert!(
            matches!(err, Error::CborDecode(ref s) if s.contains("not supported")),
            "got {err:?}"
        );
    }

    #[test]
    fn default_params_are_owasp_2023_argon2id() {
        let d = Argon2Params::default();
        assert_eq!(d.m_kib, 19_456);
        assert_eq!(d.t, 2);
        assert_eq!(d.p, 1);
    }
}
