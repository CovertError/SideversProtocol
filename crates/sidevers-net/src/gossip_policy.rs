//! Phase 1.A3: gossip-fanout web-of-trust filter (spec §6.9.3).
//!
//! When a node receives a novel public broadcast, it fans it out to all
//! currently-connected gossip peers. Without a policy, that's a free
//! amplifier for any well-formed envelope. This module adds a tunable
//! filter the operator (or the Node setup) can choose between:
//!
//!   - `Open` — fan to all currently-connected gossip peers (default
//!     behavior prior to Phase 1.A3, kept for tests + paper-protocol
//!     parity).
//!   - `ExcludeRefused` — skip peers whose reputation table has marked
//!     them refused. Sensible default for a production deployment: if
//!     we've already decided a peer is misbehaving, we shouldn't waste
//!     bandwidth pushing our broadcasts to them.
//!   - `RelationshipsOnly` — only fan to peers that appear in the
//!     local side's relationship table (the "follow graph"). This is
//!     the strict §6.9.3 interpretation; spam-resistant but bridges
//!     fewer nodes.
//!
//! The chosen mode is consulted at fanout time only — it doesn't
//! affect ingestion (which is gated separately by reputation +
//! freshness + replay).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GossipPropagation {
    /// No filter; fan to every currently-connected gossip peer except
    /// the originator. Default for backward compatibility.
    Open,
    /// Skip currently-refused peers (per the reputation table).
    ExcludeRefused,
    /// Only fan to peers that appear in the local side's relationship
    /// table — the spec §6.9.3 web-of-trust interpretation.
    RelationshipsOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GossipPolicy {
    pub propagation: GossipPropagation,
}

impl Default for GossipPolicy {
    fn default() -> Self {
        Self {
            propagation: GossipPropagation::Open,
        }
    }
}

impl GossipPolicy {
    pub fn open() -> Self {
        Self {
            propagation: GossipPropagation::Open,
        }
    }
    pub fn exclude_refused() -> Self {
        Self {
            propagation: GossipPropagation::ExcludeRefused,
        }
    }
    pub fn relationships_only() -> Self {
        Self {
            propagation: GossipPropagation::RelationshipsOnly,
        }
    }
}
