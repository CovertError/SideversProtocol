//! QUIC transport setup (protocol spec §4.2).
//!
//! Sidevers runs over QUIC (RFC 9000) with TLS 1.3. The TLS layer
//! authenticates that you've reached *some* Sidevers node; the Sidevers
//! handshake on top (`handshake` module) authenticates the specific *side*.
//!
//! Because TLS isn't carrying identity information for us, we use self-signed
//! certificates and skip cert validation on the client side. Don't conflate
//! the TLS pubkey with a Sidevers identity — they're unrelated.

use std::net::SocketAddr;
use std::sync::Arc;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, Endpoint, ServerConfig};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::{DigitallySignedStruct, SignatureScheme};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};

use crate::error::{Error, Result};

/// ALPN identifier for Sidevers v1.
pub const ALPN: &[u8] = b"sidevers/1";

/// Build a `quinn::Endpoint` configured as a Sidevers v1 listener AND
/// outbound dialer. A single endpoint serves both roles on the same UDP
/// socket; this matters for connection lifetime — dropping a separate
/// client endpoint would terminate in-flight outbound connections.
///
/// Generates a fresh self-signed certificate on each call (the cert
/// authenticates the QUIC channel only; Sidevers identity is the side key).
pub fn build_server_endpoint(bind_addr: SocketAddr) -> Result<Endpoint> {
    let (cert, key) = make_self_signed_cert()?;

    let mut server_crypto = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|e| Error::TlsConfig(e.to_string()))?
    .with_no_client_auth()
    .with_single_cert(vec![cert], key)?;
    server_crypto.alpn_protocols = vec![ALPN.to_vec()];
    // Spec §4.7: no 0-RTT in v1.
    server_crypto.max_early_data_size = 0;

    let quic_server = QuicServerConfig::try_from(server_crypto)
        .map_err(|e| Error::TlsConfig(format!("QUIC server config: {e}")))?;
    let mut server_config = ServerConfig::with_crypto(Arc::new(quic_server));
    server_config.transport_config(make_transport_config().into());

    let mut endpoint = Endpoint::server(server_config, bind_addr).map_err(Error::Io)?;
    endpoint.set_default_client_config(build_client_config()?);
    Ok(endpoint)
}

/// Build a standalone client `Endpoint` (no server role). Used by transient
/// CLI commands that don't need to accept incoming traffic.
pub fn build_client_endpoint() -> Result<Endpoint> {
    let mut endpoint = Endpoint::client((std::net::Ipv6Addr::UNSPECIFIED, 0).into())
        .or_else(|_| Endpoint::client((std::net::Ipv4Addr::UNSPECIFIED, 0).into()))?;
    endpoint.set_default_client_config(build_client_config()?);
    Ok(endpoint)
}

fn build_client_config() -> Result<ClientConfig> {
    let mut client_crypto = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|e| Error::TlsConfig(e.to_string()))?
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
    .with_no_client_auth();
    client_crypto.alpn_protocols = vec![ALPN.to_vec()];
    client_crypto.enable_early_data = false;

    let quic_client = QuicClientConfig::try_from(client_crypto)
        .map_err(|e| Error::TlsConfig(format!("QUIC client config: {e}")))?;
    let mut config = ClientConfig::new(Arc::new(quic_client));
    config.transport_config(make_transport_config().into());
    Ok(config)
}

fn make_transport_config() -> quinn::TransportConfig {
    let mut t = quinn::TransportConfig::default();
    // Tighten timeouts a bit; defaults are generous. 30s comfortably fits
    // quinn's IdleTimeout range (which is at most a few hours).
    #[allow(clippy::expect_used)]
    let idle = std::time::Duration::from_secs(30)
        .try_into()
        .expect("30s fits quinn IdleTimeout range");
    t.max_idle_timeout(Some(idle));
    t.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
    t
}

fn make_self_signed_cert() -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    let certified = rcgen::generate_simple_self_signed(vec!["sidevers".to_string()])?;
    let cert_der: CertificateDer<'static> = certified.cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into());
    Ok((cert_der, key_der))
}

/// A `ServerCertVerifier` that accepts any well-formed certificate. The
/// Sidevers handshake authenticates the peer's identity at a higher layer.
#[derive(Debug)]
struct AcceptAnyServerCert;

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
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
