//! Post-handshake session state and per-message stream framing.
//!
//! A `Session` holds the QUIC connection, the derived session key (used for
//! transcript binding only — the channel is already encrypted by QUIC's TLS),
//! the peer's authenticated side public key, and the negotiated intent.
//!
//! Intent enforcement (§4.4): every envelope received on a session has its
//! `MessageType.category()` checked against the session's intent. Mismatches
//! are rejected with `Error::WrongIntent`.

use sidevers_core::Envelope;
use sidevers_core::envelope::{MessageCategory, MessageType};
use sidevers_core::keys::PUBLIC_KEY_LEN;
use sidevers_core::messages::handshake::intent;

use crate::error::{Error, Result};
use crate::framing::{recv_envelope, send_envelope};
use crate::handshake::SESSION_KEY_LEN;

/// Negotiated session intent per spec §4.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Intent {
    Direct,
    Storage,
    Gossip,
    Verse,
    PublicLayer,
}

impl Intent {
    pub fn as_u8(self) -> u8 {
        match self {
            Intent::Direct => intent::DIRECT,
            Intent::Storage => intent::STORAGE,
            Intent::Gossip => intent::GOSSIP,
            Intent::Verse => intent::VERSE,
            Intent::PublicLayer => intent::PUBLIC_LAYER,
        }
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            intent::DIRECT => Some(Intent::Direct),
            intent::STORAGE => Some(Intent::Storage),
            intent::GOSSIP => Some(Intent::Gossip),
            intent::VERSE => Some(Intent::Verse),
            intent::PUBLIC_LAYER => Some(Intent::PublicLayer),
            _ => None,
        }
    }

    pub fn accepts(self, mt: MessageType) -> bool {
        match (self, mt.category()) {
            (Intent::Direct, MessageCategory::Direct) => true,
            (Intent::Storage, MessageCategory::Storage) => true,
            // Gossip carries peer-exchange, rendezvous, store-and-forward
            // (Discovery 0x40–0x4F) plus broadcast public posts.
            (Intent::Gossip, MessageCategory::Discovery) => true,
            (Intent::Gossip, MessageCategory::Public) => true,
            (Intent::Verse, MessageCategory::Verse) => true,
            (Intent::PublicLayer, MessageCategory::Public) => true,
            // Handshake messages are not valid after handshake completes.
            _ => false,
        }
    }
}

pub struct Session {
    pub connection: quinn::Connection,
    pub session_key: [u8; SESSION_KEY_LEN],
    pub peer_side: [u8; PUBLIC_KEY_LEN],
    pub intent: Intent,
    /// Capabilities the peer advertised in Hello / HelloBack (Phase 1.D).
    /// Currently observational — handlers may consult to gate optional
    /// features the spec ties to advertised capabilities.
    pub peer_capabilities: std::collections::BTreeMap<String, u64>,
}

impl Session {
    pub fn new(
        connection: quinn::Connection,
        session_key: [u8; SESSION_KEY_LEN],
        peer_side: [u8; PUBLIC_KEY_LEN],
        intent: Intent,
    ) -> Self {
        Self {
            connection,
            session_key,
            peer_side,
            intent,
            peer_capabilities: std::collections::BTreeMap::new(),
        }
    }

    /// Construct a session with peer-capabilities set. Used by the
    /// handshake; external callers usually go through `new`.
    pub fn with_capabilities(
        connection: quinn::Connection,
        session_key: [u8; SESSION_KEY_LEN],
        peer_side: [u8; PUBLIC_KEY_LEN],
        intent: Intent,
        peer_capabilities: std::collections::BTreeMap<String, u64>,
    ) -> Self {
        Self {
            connection,
            session_key,
            peer_side,
            intent,
            peer_capabilities,
        }
    }

    /// Open a fresh bidirectional QUIC stream and send a single envelope on it.
    /// Returns the stream pair so the caller may continue to read responses.
    pub async fn open_and_send(
        &self,
        env: &Envelope,
    ) -> Result<(quinn::SendStream, quinn::RecvStream)> {
        if !self.intent.accepts(env.message_type) {
            return Err(Error::WrongIntent {
                got: env.message_type.0,
                intent: self.intent.as_u8(),
            });
        }
        let (mut send, recv) = self.connection.open_bi().await?;
        send_envelope(&mut send, env).await?;
        Ok((send, recv))
    }

    /// Accept the next bidirectional stream and read one envelope from it.
    pub async fn accept_one(&self) -> Result<(quinn::SendStream, quinn::RecvStream, Envelope)> {
        let (send, mut recv) = self.connection.accept_bi().await?;
        let env = recv_envelope(&mut recv).await?;
        if !self.intent.accepts(env.message_type) {
            return Err(Error::WrongIntent {
                got: env.message_type.0,
                intent: self.intent.as_u8(),
            });
        }
        Ok((send, recv, env))
    }
}
