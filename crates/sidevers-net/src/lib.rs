//! Sidevers network layer: QUIC transport (§4.2), handshake state machine
//! (§4.3), single-intent sessions (§4.4), and the storage protocol (§5.4–§5.5).
//!
//! Month 3 of Phase 1. Peer exchange / NAT / store-and-forward / gossip
//! are Month 4 (§6).

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod error;
pub mod forward;
mod framing;
pub mod gossip;
pub mod handshake;
pub mod node;
pub mod peers;
pub mod session;
pub mod storage_protocol;
pub mod transport;
pub mod verse;

pub use error::{Error, Result};
pub use forward::Mailbox;
pub use gossip::GossipState;
pub use handshake::{HANDSHAKE_TIMEOUT, run_initiator, run_responder};
pub use node::{
    DirectMessageReceived, Node, VerseMembership, VersePostReceived, accept_one_push,
    apply_verse_key_rotation, decode_verse_amend, fetch_contract, fetch_object, leave_verse,
    offer_object, post_to_verse, publish_broadcast, query_peers, reconsent_to_amendment,
    request_join, request_rendezvous, retract_object, send_dm, submit_forward,
};
pub use peers::PeerTable;
pub use session::{Intent, Session};
pub use transport::ALPN;
pub use verse::VerseHost;
