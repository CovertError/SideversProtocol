//! Errors for the network layer.

use thiserror::Error;

pub type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("quinn connect: {0}")]
    Connect(#[from] quinn::ConnectError),

    #[error("quinn connection: {0}")]
    Connection(#[from] quinn::ConnectionError),

    #[error("quinn write: {0}")]
    Write(#[from] quinn::WriteError),

    #[error("quinn read: {0}")]
    Read(#[from] quinn::ReadError),

    #[error("quinn read exact: {0}")]
    ReadExact(#[from] quinn::ReadExactError),

    #[error("rcgen: {0}")]
    Rcgen(#[from] rcgen::Error),

    #[error("rustls: {0}")]
    Rustls(#[from] rustls::Error),

    #[error("tls config: {0}")]
    TlsConfig(String),

    #[error("core: {0}")]
    Core(#[from] sidevers_core::Error),

    #[error("storage: {0}")]
    Storage(#[from] sidevers_storage::Error),

    #[error("handshake declined by peer: {0}")]
    HandshakeDeclined(String),

    #[error("handshake timeout (>10s)")]
    HandshakeTimeout,

    #[error("handshake protocol error: {0}")]
    HandshakeProtocol(&'static str),

    #[error("session: wrong message type 0x{got:02X} for intent {intent}")]
    WrongIntent { got: u8, intent: u8 },

    #[error("envelope too large: {got} bytes (max {max})")]
    EnvelopeTooLarge { got: u32, max: u32 },

    #[error("replay detected for (from, nonce)")]
    Replay,

    #[error("invariant: {0}")]
    Invariant(&'static str),

    #[error("address: {0}")]
    Address(String),
}
