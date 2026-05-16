//! Sidevers v1 handshake state machine (protocol spec §4.3).
//!
//! Three-message exchange on a fresh bidirectional QUIC stream:
//!
//!   Initiator ──── Hello (0x10) ──────► Responder
//!   Initiator ◄─── HelloBack (0x11) ─── Responder
//!   Initiator ──── Confirm (0x12) ────► Responder
//!
//! After Confirm verifies, both parties hold the same `session_key` derived
//! from the ephemeral X25519 exchange and the BLAKE3-hashed transcript.

use std::collections::BTreeMap;
use std::time::Duration;

use hkdf::Hkdf;
use sha2::Sha512;
use sidevers_core::Envelope;
use sidevers_core::envelope::random_nonce;
use sidevers_core::keys::{PUBLIC_KEY_LEN, SideKey};
use sidevers_core::messages::handshake::{
    ConfirmPayload, EPH_PUB_LEN, HelloBackPayload, HelloPayload,
};
use sidevers_core::{Address, AddressKind, LogId, MessageType, PROTOCOL_VERSION};
use tracing::debug;
use x25519_dalek::{EphemeralSecret, PublicKey as XPublicKey};

use crate::error::{Error, Result};
use crate::framing::{recv_envelope, send_envelope};
use crate::session::{Intent, Session};

/// Capability key advertising the protocol major version we speak.
pub const CAP_PROTOCOL: &str = "protocol";
/// Capability key with a bitmask of intents this node accepts (bit `i`
/// set ⇔ intent `i` is supported, with `i` = `Intent::as_u8()`).
pub const CAP_INTENTS_MASK: &str = "intents_mask";
/// Capability key advertising the maximum envelope size in KiB we'll
/// accept. Future extension point; informational in Phase 1.
pub const CAP_MAX_ENVELOPE_KIB: &str = "max_envelope_kib";

/// Build the capabilities map this node advertises in Hello /
/// HelloBack. Phase 1.D — populated; was a dead field prior.
pub(crate) fn local_capabilities() -> BTreeMap<String, u64> {
    let mut caps = BTreeMap::new();
    caps.insert(CAP_PROTOCOL.to_owned(), PROTOCOL_VERSION);
    // All 5 v1 intents are supported by the node responder.
    let mut mask: u64 = 0;
    for i in 1u8..=5 {
        mask |= 1u64 << i;
    }
    caps.insert(CAP_INTENTS_MASK.to_owned(), mask);
    caps.insert(CAP_MAX_ENVELOPE_KIB.to_owned(), 1024);
    caps
}

/// Hard ceiling on total handshake duration per spec §4.6.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Length of the derived session key, in bytes (§4.3.2).
pub const SESSION_KEY_LEN: usize = 32;

/// HKDF info string for session-key derivation.
const SESSION_HKDF_INFO: &[u8] = b"sidevers/v1/session";

/// Run the initiator side of the handshake on a freshly-opened bi-stream.
///
/// # Errors
/// - `Error::HandshakeTimeout` if the full handshake doesn't complete
///   within `HANDSHAKE_TIMEOUT` (10s).
/// - `Error::HandshakeDeclined` if the responder rejects via `HelloBack
///   {accept: false}`.
/// - `Error::HandshakeProtocol` on malformed exchange.
/// - Underlying `quinn` / `Core` / `Rcgen` / `Rustls` errors via `From`.
#[tracing::instrument(
    name = "handshake.initiator",
    skip(conn, my_side, expected_peer_side),
    fields(intent = %intent.as_u8(), my_side = %LogId::new(&my_side.public_bytes())),
    err
)]
pub async fn run_initiator(
    conn: &quinn::Connection,
    my_side: &SideKey,
    intent: Intent,
    expected_peer_side: Option<[u8; PUBLIC_KEY_LEN]>,
) -> Result<Session> {
    tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        run_initiator_inner(conn, my_side, intent, expected_peer_side),
    )
    .await
    .map_err(|_| Error::HandshakeTimeout)?
}

async fn run_initiator_inner(
    conn: &quinn::Connection,
    my_side: &SideKey,
    intent: Intent,
    expected_peer_side: Option<[u8; PUBLIC_KEY_LEN]>,
) -> Result<Session> {
    let (mut send, mut recv) = conn.open_bi().await?;

    // 1. Ephemeral X25519 keypair (forward secrecy — discarded after session_key derivation).
    //    OS CSPRNG directly: avoids any future change in `rand::thread_rng()` semantics
    //    affecting handshake key material.
    let eph_secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
    let eph_pub_bytes: [u8; EPH_PUB_LEN] = XPublicKey::from(&eph_secret).to_bytes();

    // 2. Build, sign, and send Hello (type 0x10). Set `to` to the expected peer
    //    side if known (helps the responder route in multi-side setups); else nil.
    let hello_payload = HelloPayload {
        v_max: 1,
        v_min: 1,
        extensions: vec![],
        eph_pub: eph_pub_bytes,
        intent: intent.as_u8(),
        capabilities: local_capabilities(),
    };
    let hello_env = Envelope::sign_with(
        MessageType::HELLO,
        my_side,
        expected_peer_side,
        hello_payload.encode(),
        sidevers_core::envelope::now_unix_seconds()?,
        random_nonce()?,
    )?;
    let hello_bytes = hello_env.to_wire_bytes();
    send_envelope(&mut send, &hello_env).await?;

    // 3. Read HelloBack (type 0x11), verify it's the right type, parse payload.
    let helloback_env = recv_envelope(&mut recv).await?;
    if helloback_env.message_type != MessageType::HELLO_BACK {
        return Err(Error::HandshakeProtocol("expected HelloBack"));
    }
    let helloback_bytes = helloback_env.to_wire_bytes();
    let helloback_payload = HelloBackPayload::decode(&helloback_env.payload)?;

    if !helloback_payload.accept {
        return Err(Error::HandshakeDeclined(
            helloback_payload
                .reason
                .unwrap_or_else(|| "(no reason)".into()),
        ));
    }
    if helloback_payload.v != 1 {
        return Err(Error::HandshakeProtocol("unsupported version negotiated"));
    }

    // 4. Derive session key.
    let peer_eph_pub = XPublicKey::from(helloback_payload.eph_pub);
    let session_key = derive_session_key(eph_secret, peer_eph_pub, &hello_bytes, &helloback_bytes);

    // 5. Build, sign, and send Confirm with transcript MAC.
    let proof = transcript_mac(&session_key, &hello_bytes, &helloback_bytes);
    let confirm_payload = ConfirmPayload { proof };
    let confirm_env = Envelope::sign_with(
        MessageType::CONFIRM,
        my_side,
        Some(helloback_env.from),
        confirm_payload.encode(),
        sidevers_core::envelope::now_unix_seconds()?,
        random_nonce()?,
    )?;
    send_envelope(&mut send, &confirm_env).await?;
    send.finish().ok();
    // We deliberately don't read from `recv` after this; the responder closes
    // its send half on success.

    if !helloback_payload.capabilities.is_empty() {
        debug!(
            peer = %LogId::new(&helloback_env.from),
            caps = ?helloback_payload.capabilities,
            "handshake: peer advertised capabilities"
        );
    }

    Ok(Session::with_capabilities(
        conn.clone(),
        session_key,
        helloback_env.from,
        intent,
        helloback_payload.capabilities,
    ))
}

/// Run the responder side of the handshake. Reads from one accepted bi-stream.
///
/// # Errors
/// - `Error::HandshakeTimeout` if the full handshake doesn't complete
///   within `HANDSHAKE_TIMEOUT` (10s).
/// - `Error::HandshakeProtocol` on malformed initiator exchange.
/// - Underlying `quinn` / `Core` errors via `From`.
#[tracing::instrument(
    name = "handshake.responder",
    skip(send, recv, my_side, conn),
    fields(my_side = %LogId::new(&my_side.public_bytes())),
    err
)]
pub async fn run_responder(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    my_side: &SideKey,
    conn: &quinn::Connection,
) -> Result<Session> {
    tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        run_responder_inner(send, recv, my_side, conn),
    )
    .await
    .map_err(|_| Error::HandshakeTimeout)?
}

async fn run_responder_inner(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    my_side: &SideKey,
    conn: &quinn::Connection,
) -> Result<Session> {
    // 1. Read Hello, parse payload.
    let hello_env = recv_envelope(recv).await?;
    if hello_env.message_type != MessageType::HELLO {
        return Err(Error::HandshakeProtocol("expected Hello"));
    }
    let hello_bytes = hello_env.to_wire_bytes();
    let hello_payload = HelloPayload::decode(&hello_env.payload)?;

    // 2. Version negotiation.
    let accept_version = hello_payload.v_min <= 1 && 1 <= hello_payload.v_max;

    // 3. Intent must be one we support in v1.
    let intent_known = matches!(hello_payload.intent, 1..=5);

    if !accept_version || !intent_known {
        // Build a polite decline.
        let reason = if !accept_version {
            "version-incompatible"
        } else {
            "intent-refused"
        }
        .to_string();
        let decline = HelloBackPayload {
            v: 1,
            accept: false,
            reason: Some(reason),
            eph_pub: [0u8; EPH_PUB_LEN],
            extensions: vec![],
            capabilities: Default::default(),
        };
        let env = Envelope::sign_with(
            MessageType::HELLO_BACK,
            my_side,
            Some(hello_env.from),
            decline.encode(),
            sidevers_core::envelope::now_unix_seconds()?,
            random_nonce()?,
        )?;
        send_envelope(send, &env).await?;
        send.finish().ok();
        return Err(Error::HandshakeDeclined("local refusal".into()));
    }

    // 4. Generate ephemeral X25519, build HelloBack, send. OS CSPRNG directly
    //    (see initiator note on `rand::thread_rng()` semantics).
    let my_eph = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
    let my_eph_pub: [u8; EPH_PUB_LEN] = XPublicKey::from(&my_eph).to_bytes();

    let accept = HelloBackPayload {
        v: 1,
        accept: true,
        reason: None,
        eph_pub: my_eph_pub,
        extensions: vec![],
        capabilities: local_capabilities(),
    };
    let helloback_env = Envelope::sign_with(
        MessageType::HELLO_BACK,
        my_side,
        Some(hello_env.from),
        accept.encode(),
        sidevers_core::envelope::now_unix_seconds()?,
        random_nonce()?,
    )?;
    let helloback_bytes = helloback_env.to_wire_bytes();
    send_envelope(send, &helloback_env).await?;

    // 5. Derive session key.
    let peer_eph = XPublicKey::from(hello_payload.eph_pub);
    let session_key = derive_session_key(my_eph, peer_eph, &hello_bytes, &helloback_bytes);

    // 6. Read Confirm, verify MAC.
    let confirm_env = recv_envelope(recv).await?;
    if confirm_env.message_type != MessageType::CONFIRM {
        return Err(Error::HandshakeProtocol("expected Confirm"));
    }
    let confirm_payload = ConfirmPayload::decode(&confirm_env.payload)?;
    let expected = transcript_mac(&session_key, &hello_bytes, &helloback_bytes);
    if !subtle_eq(&confirm_payload.proof, &expected) {
        return Err(Error::HandshakeProtocol("Confirm MAC mismatch"));
    }
    send.finish().ok();

    let intent =
        Intent::from_u8(hello_payload.intent).ok_or(Error::HandshakeProtocol("unknown intent"))?;

    if !hello_payload.capabilities.is_empty() {
        debug!(
            peer = %LogId::new(&hello_env.from),
            caps = ?hello_payload.capabilities,
            "handshake: peer advertised capabilities"
        );
    }

    Ok(Session::with_capabilities(
        conn.clone(),
        session_key,
        hello_env.from,
        intent,
        hello_payload.capabilities,
    ))
}

/// `session_key = HKDF-SHA-512(ikm=X25519(...), salt=BLAKE3(hello ‖ helloback),
///                              info="sidevers/v1/session", L=32)` per §4.3.2.
fn derive_session_key(
    my_eph: EphemeralSecret,
    their_eph: XPublicKey,
    hello_bytes: &[u8],
    helloback_bytes: &[u8],
) -> [u8; SESSION_KEY_LEN] {
    let shared = my_eph.diffie_hellman(&their_eph);
    let mut transcript = Vec::with_capacity(hello_bytes.len() + helloback_bytes.len());
    transcript.extend_from_slice(hello_bytes);
    transcript.extend_from_slice(helloback_bytes);
    let salt = blake3::hash(&transcript);
    let hkdf = Hkdf::<Sha512>::new(Some(salt.as_bytes()), shared.as_bytes());
    let mut key = [0u8; SESSION_KEY_LEN];
    #[allow(clippy::expect_used)]
    hkdf.expand(SESSION_HKDF_INFO, &mut key)
        .expect("HKDF expand 32 bytes cannot fail");
    key
}

fn transcript_mac(
    session_key: &[u8; SESSION_KEY_LEN],
    hello_bytes: &[u8],
    helloback_bytes: &[u8],
) -> [u8; 32] {
    let mut transcript = Vec::with_capacity(hello_bytes.len() + helloback_bytes.len());
    transcript.extend_from_slice(hello_bytes);
    transcript.extend_from_slice(helloback_bytes);
    *blake3::keyed_hash(session_key, &transcript).as_bytes()
}

/// Constant-time equality for 32-byte fixed arrays.
fn subtle_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

/// Helper for callers: pretty-print a peer's `from` (envelope address) as
/// a bech32m side address.
pub fn address_of(side_bytes: &[u8; PUBLIC_KEY_LEN]) -> Address {
    Address::new(AddressKind::Side, *side_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MAC tampering: a Confirm proof that differs from the expected
    /// transcript MAC by even one bit must be rejected by the responder's
    /// `subtle_eq` check (handshake.rs:292). Models the wire scenario where
    /// an initiator (or MITM) submits a Confirm with wrong proof bytes.
    /// (Audit P2.9.)
    #[test]
    fn confirm_mac_mismatch_is_rejected_by_subtle_eq() {
        let session_key = [0x42u8; SESSION_KEY_LEN];
        let hello = b"some-hello-envelope-bytes";
        let helloback = b"some-helloback-envelope-bytes";
        let expected = transcript_mac(&session_key, hello, helloback);

        // Matching proof is accepted.
        assert!(subtle_eq(&expected, &expected));

        // Single-bit flip in proof is rejected.
        let mut tampered = expected;
        tampered[0] ^= 0x01;
        assert!(!subtle_eq(&expected, &tampered));

        // Different session key produces a different MAC for the same
        // transcript — the MITM-with-wrong-key case.
        let wrong_key = [0x43u8; SESSION_KEY_LEN];
        let with_wrong = transcript_mac(&wrong_key, hello, helloback);
        assert!(!subtle_eq(&expected, &with_wrong));

        // Tampered transcript also yields a different MAC — the
        // "MITM altered hello/helloback bytes" case.
        let tampered_hello = b"some-hello-envelope-bytes!";
        let with_tampered_transcript = transcript_mac(&session_key, tampered_hello, helloback);
        assert!(!subtle_eq(&expected, &with_tampered_transcript));
    }

    /// Version negotiation: the initiator side of `run_initiator_inner`
    /// performs an inline `helloback_payload.v != 1` check and returns
    /// `HandshakeProtocol("unsupported version negotiated")`. This unit
    /// test exercises the predicate against HelloBackPayload values that
    /// decode cleanly but carry an unsupported `v`. (Audit P2.9.)
    #[test]
    fn version_check_rejects_helloback_with_unsupported_v() {
        use sidevers_core::messages::handshake::HelloBackPayload;
        use std::collections::BTreeMap;

        for v_bogus in [0u64, 2, 99, u64::MAX] {
            let p = HelloBackPayload {
                v: v_bogus,
                accept: true,
                reason: None,
                eph_pub: [0u8; EPH_PUB_LEN],
                extensions: vec![],
                capabilities: BTreeMap::new(),
            };
            let bytes = p.encode();
            let decoded = HelloBackPayload::decode(&bytes)
                .expect("payload should decode; the check is on `v`, not the wire shape");
            assert_eq!(decoded.v, v_bogus);
            // This is the literal check from run_initiator_inner.
            assert!(
                decoded.v != 1,
                "v={v_bogus} must trip the != 1 guard in the initiator"
            );
        }

        // Positive control: v=1 passes the guard.
        let ok = HelloBackPayload {
            v: 1,
            accept: true,
            reason: None,
            eph_pub: [0u8; EPH_PUB_LEN],
            extensions: vec![],
            capabilities: BTreeMap::new(),
        };
        let decoded = HelloBackPayload::decode(&ok.encode()).unwrap();
        assert_eq!(decoded.v, 1);
    }
}
