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
pub mod hygiene;
pub mod node;
pub mod peers;
pub mod relationships;
pub mod session;
pub mod side;
pub mod side_store;
pub mod storage_protocol;
pub mod transport;
pub mod verse;

pub use error::{Error, Result};
pub use forward::Mailbox;
pub use gossip::GossipState;
pub use handshake::{HANDSHAKE_TIMEOUT, run_initiator, run_responder};
pub use hygiene::{
    DEFAULT_PUBLISH_JITTER_MS, apply_jitter_ms, apply_publish_jitter, is_jitter_disabled,
    set_jitter_disabled,
};
pub use node::{
    DirectMessageReceived, Node, ProfileDelivered, VerseMembership, VersePostReceived,
    accept_one_push, announce_retirement, apply_verse_key_rotation, decode_verse_amend,
    fetch_contract, fetch_object, fetch_profile, leave_verse, offer_object, post_to_verse,
    publish_broadcast, query_peers, reconsent_to_amendment, request_join, request_rendezvous,
    retract_object, send_dm, submit_forward,
};
pub use peers::PeerTable;
pub use relationships::{DORMANT_AFTER_SECS, RelationshipTable, SideLifecycle, SideRelationship};
pub use session::{Intent, Session};
pub use side::{CoHolderRecord, PendingPairing, Side};
pub use side_store::{SCHEMA_VERSION, SideStore, StoredSide};
pub use transport::ALPN;
pub use verse::VerseHost;
