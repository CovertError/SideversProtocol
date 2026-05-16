//! Phase 1.H2: TLS certificate pinning + rotation.
//!
//! The Sidevers protocol authenticates peers at the *side* layer
//! (Hello/HelloBack/Confirm with Ed25519 signatures), so by default
//! the TLS layer accepts any self-signed cert. This module adds an
//! opt-in defense-in-depth: pin the expected SHA-256 of a peer's
//! TLS cert and refuse the QUIC handshake if it doesn't match.
//!
//! Pin storage is per-`(peer_addr, expected_hash)`. Empty pin table =
//! pre-1.H2 behavior (accept anything). With pins set, the verifier
//! enforces them.
//!
//! Rotation: nodes can call [`rotate_self_signed_cert`] to mint a
//! fresh cert. Wiring the new cert into a running `quinn::Endpoint`
//! requires `Endpoint::set_server_config`; the `Node::rotate_certificate`
//! convenience method does that and returns the new pin hash so
//! operators can re-distribute it.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::{DigitallySignedStruct, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use tokio::sync::Mutex;

/// Compute the BLAKE3 fingerprint of a DER-encoded certificate. Used
/// as the pin value; 32 bytes, collision-resistant, fast.
pub fn fingerprint(cert: &[u8]) -> [u8; 32] {
    *blake3::hash(cert).as_bytes()
}

/// Cheap, clonable pin table. Maps peer socket address → expected
/// cert fingerprint. Lookups are async-locked; expected size is small
/// (one entry per known peer at most).
#[derive(Debug, Clone, Default)]
pub struct CertPinTable {
    inner: Arc<Mutex<HashMap<SocketAddr, [u8; 32]>>>,
}

impl CertPinTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Pin `expected_hash` as the required cert fingerprint for
    /// `peer_addr`. Replaces any prior pin for the same address.
    pub async fn pin(&self, peer_addr: SocketAddr, expected_hash: [u8; 32]) {
        self.inner.lock().await.insert(peer_addr, expected_hash);
    }

    /// Remove the pin for `peer_addr`, if any. Returns the prior
    /// value or `None`.
    pub async fn unpin(&self, peer_addr: SocketAddr) -> Option<[u8; 32]> {
        self.inner.lock().await.remove(&peer_addr)
    }

    /// Look up the expected hash for `peer_addr`.
    pub async fn get(&self, peer_addr: SocketAddr) -> Option<[u8; 32]> {
        self.inner.lock().await.get(&peer_addr).copied()
    }

    /// Total pins. Diagnostic / metrics use only.
    pub async fn len(&self) -> usize {
        self.inner.lock().await.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }
}

/// A `ServerCertVerifier` that enforces pins where present and
/// otherwise falls back to "accept any well-formed cert" (current
/// pre-1.H2 default behavior). Verification is synchronous (rustls
/// API), so we do a synchronous best-effort lookup against a snapshot
/// of the pin table captured at QUIC client config build time. For
/// runtime pin updates between dials, rebuild the client config.
#[derive(Debug)]
pub struct PinnedOrAccept {
    /// Snapshot of pin table at the time this verifier was built.
    /// Synchronous lookup needs sync data.
    snapshot: HashMap<SocketAddr, [u8; 32]>,
}

impl PinnedOrAccept {
    pub fn from_snapshot(snapshot: HashMap<SocketAddr, [u8; 32]>) -> Self {
        Self { snapshot }
    }

    /// Empty pin set: equivalent to "accept any cert" — what every
    /// pre-1.H2 client did.
    pub fn permissive() -> Self {
        Self {
            snapshot: HashMap::new(),
        }
    }
}

impl ServerCertVerifier for PinnedOrAccept {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        // The server_name passed by rustls is "sidevers" (a literal
        // string, not a socket address). We can't look up pins by it.
        // The Node-level verifier therefore matches pins to socket
        // addresses by constructing the verifier per-dial in
        // future-1.H2-iter — for now `permissive` is the no-pin path
        // and pins are enforced only when the caller built the
        // verifier with a single-entry snapshot keyed on the peer
        // being dialed.
        let _ = server_name;
        if self.snapshot.is_empty() {
            return Ok(ServerCertVerified::assertion());
        }
        let presented = fingerprint(end_entity.as_ref());
        // If any pinned hash matches, accept. (Most snapshots are
        // single-entry, built for one dial.)
        if self
            .snapshot
            .values()
            .any(|expected| *expected == presented)
        {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "TLS cert pin mismatch (Phase 1.H2)".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ED25519,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pin_round_trip() {
        let t = CertPinTable::new();
        assert!(t.is_empty().await);
        let addr: SocketAddr = "127.0.0.1:50001".parse().unwrap();
        let h = fingerprint(b"some-cert-der-bytes");
        t.pin(addr, h).await;
        assert_eq!(t.len().await, 1);
        assert_eq!(t.get(addr).await, Some(h));
        assert_eq!(t.unpin(addr).await, Some(h));
        assert!(t.is_empty().await);
    }

    #[test]
    fn verifier_accepts_when_empty_pin_set() {
        let v = PinnedOrAccept::permissive();
        let cert = CertificateDer::from(b"any-cert".to_vec());
        let server_name = ServerName::try_from("sidevers").unwrap();
        let now = UnixTime::now();
        assert!(
            v.verify_server_cert(&cert, &[], &server_name, &[], now)
                .is_ok()
        );
    }

    #[test]
    fn verifier_rejects_mismatched_pin() {
        let cert = CertificateDer::from(b"real-cert".to_vec());
        let wrong = fingerprint(b"impostor-cert");
        let mut snap = HashMap::new();
        snap.insert("127.0.0.1:9".parse().unwrap(), wrong);
        let v = PinnedOrAccept::from_snapshot(snap);
        let server_name = ServerName::try_from("sidevers").unwrap();
        let now = UnixTime::now();
        let err = v
            .verify_server_cert(&cert, &[], &server_name, &[], now)
            .unwrap_err();
        assert!(matches!(err, rustls::Error::General(_)));
    }

    #[test]
    fn verifier_accepts_matched_pin() {
        let cert_bytes = b"real-cert".to_vec();
        let h = fingerprint(&cert_bytes);
        let mut snap = HashMap::new();
        snap.insert("127.0.0.1:9".parse().unwrap(), h);
        let v = PinnedOrAccept::from_snapshot(snap);
        let cert = CertificateDer::from(cert_bytes);
        let server_name = ServerName::try_from("sidevers").unwrap();
        let now = UnixTime::now();
        assert!(
            v.verify_server_cert(&cert, &[], &server_name, &[], now)
                .is_ok()
        );
    }
}
