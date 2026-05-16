//! Sidevers network layer: QUIC transport (§4.2), handshake state machine
//! (§4.3), single-intent sessions (§4.4), and the storage protocol (§5.4–§5.5).
//!
//! Month 3 of Phase 1. Peer exchange / NAT / store-and-forward / gossip
//! are Month 4 (§6).

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod cert;
pub mod connection_pool;
pub mod error;
pub mod forward;
mod framing;
pub mod fs_perms;
pub mod gossip;
pub mod gossip_policy;
pub mod handshake;
pub mod handshake_limit;
pub mod hole_punch;
pub mod hygiene;
pub mod inbox_store;
pub mod metrics;
pub mod node;
pub mod peers;
pub mod provenance;
pub mod relationships;
pub mod replay_journal;
pub mod reputation;
pub mod session;
pub mod side;
pub mod side_store;
pub mod storage_protocol;
pub mod transport;
pub mod verse;
pub mod verse_post_store;

pub use cert::{CertPinTable, PinnedOrAccept, fingerprint as cert_fingerprint};
pub use connection_pool::ConnectionPool;
pub use error::{Error, Result};
pub use forward::Mailbox;
pub use gossip::GossipState;
pub use gossip_policy::{GossipPolicy, GossipPropagation};
pub use handshake::{HANDSHAKE_TIMEOUT, run_initiator, run_responder};
pub use handshake_limit::{
    HANDSHAKE_BURST, HANDSHAKE_IDLE_FORGET_SECS, HANDSHAKE_REFILL_PER_SEC, HandshakeLimiter,
};
pub use hole_punch::{
    HOLE_PUNCH_ATTEMPT_TIMEOUT, HOLE_PUNCH_ATTEMPTS, HOLE_PUNCH_BACKOFF, HolePunchConfig,
    hole_punch_with,
};
pub use hygiene::{
    DEFAULT_PUBLISH_JITTER_MS, apply_jitter_ms, apply_publish_jitter, is_jitter_disabled,
    set_jitter_disabled,
};
pub use inbox_store::{InboxEntry, InboxStore};
pub use metrics::Metrics;
pub use node::{
    DirectMessageReceived, LinkageProofReceived, Node, ProfileDelivered, VerseMembership,
    VersePostReceived, accept_one_push, announce_retirement, apply_verse_key_rotation,
    decode_verse_amend, fetch_contract, fetch_object, fetch_profile, leave_verse, offer_object,
    post_to_verse, publish_broadcast, publish_linkage_proof, query_peers, reconsent_to_amendment,
    request_join, request_rendezvous, retract_object, send_dm, submit_forward,
};
pub use peers::PeerTable;
pub use provenance::PublisherTable;
pub use relationships::{DORMANT_AFTER_SECS, RelationshipTable, SideLifecycle, SideRelationship};
pub use replay_journal::SqliteReplayJournal;
pub use reputation::{
    DEFAULT_BUCKET_CAPACITY, DEFAULT_REFILL_PER_SEC, MAX_MALFORMED, MAX_SIG_FAILURES,
    PeerReputation, ReputationPolicy, ReputationTable,
};
pub use session::{Intent, Session};
pub use side::{CoHolderRecord, PendingPairing, Side};
pub use side_store::{SCHEMA_VERSION, SideStore, StoredSide};
pub use transport::ALPN;
pub use verse::VerseHost;
pub use verse_post_store::{StoredVersePost, VersePostStore};
