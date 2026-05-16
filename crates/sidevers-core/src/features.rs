//! Phase 1.G3: feature-state deprecation pipeline (spec §10.3.3).
//!
//! The protocol's published-feature lifecycle has three states:
//!
//! * **Active** — the feature is current. Implementations MUST support
//!   it on the wire and SHOULD use it.
//! * **Deprecated** — the feature still works but new code SHOULD NOT
//!   rely on it. Implementations MAY emit a diagnostic when they observe
//!   it. Tracks the protocol version that flipped the state.
//! * **Frozen** — the feature is read-only. Implementations MUST still
//!   parse / verify it (legacy state survives) but MUST NOT produce new
//!   instances. Tracks the protocol version that froze it.
//!
//! This crate ships a static `Phase 1 baseline` registry naming every
//! Phase-1 feature with its current state. Consumers query it via
//! [`FeatureRegistry::state_of`] and decide what to do — e.g. log a
//! warning on observing a `Deprecated` field, refuse to emit a
//! `Frozen` field, etc.
//!
//! Adding a feature is a one-line `register` call; deprecating /
//! freezing is one state change. The registry itself is immutable
//! after build; callers can layer additional features on top of the
//! baseline via [`FeatureRegistry::extended_with`].

use std::collections::BTreeMap;

/// Lifecycle state of one named protocol feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeatureState {
    /// Current; implementations MUST support and MAY use freely.
    Active,
    /// Still functional but discouraged. `since` is the protocol
    /// version that flipped this feature to deprecated.
    Deprecated { since_version: u64 },
    /// Read-only for legacy state. New instances MUST NOT be emitted.
    /// `since` is the protocol version that froze it.
    Frozen { since_version: u64 },
}

impl FeatureState {
    pub fn is_active(&self) -> bool {
        matches!(self, FeatureState::Active)
    }
    pub fn is_deprecated(&self) -> bool {
        matches!(self, FeatureState::Deprecated { .. })
    }
    pub fn is_frozen(&self) -> bool {
        matches!(self, FeatureState::Frozen { .. })
    }
    /// True iff implementations are still allowed to *emit* this feature
    /// on the wire (Active or Deprecated — not Frozen).
    pub fn allows_emission(&self) -> bool {
        !matches!(self, FeatureState::Frozen { .. })
    }
}

/// Immutable registry of named features → states.
#[derive(Debug, Clone, Default)]
pub struct FeatureRegistry {
    entries: BTreeMap<String, FeatureState>,
}

impl FeatureRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a registry from `(name, state)` pairs. Later entries
    /// with the same name win — useful for layering an override on top
    /// of the baseline.
    pub fn from_pairs<I, S>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (S, FeatureState)>,
        S: Into<String>,
    {
        let mut entries = BTreeMap::new();
        for (n, s) in pairs {
            entries.insert(n.into(), s);
        }
        Self { entries }
    }

    pub fn register(&mut self, name: impl Into<String>, state: FeatureState) {
        self.entries.insert(name.into(), state);
    }

    pub fn state_of(&self, name: &str) -> Option<FeatureState> {
        self.entries.get(name).copied()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(|s| s.as_str())
    }

    /// Iterate over all (name, state) pairs sorted by name.
    pub fn iter(&self) -> impl Iterator<Item = (&str, FeatureState)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), *v))
    }

    /// Return a new registry with `overrides` layered on top of `self`.
    /// Useful for tests + downstream registries.
    pub fn extended_with<I, S>(&self, overrides: I) -> Self
    where
        I: IntoIterator<Item = (S, FeatureState)>,
        S: Into<String>,
    {
        let mut entries = self.entries.clone();
        for (n, s) in overrides {
            entries.insert(n.into(), s);
        }
        Self { entries }
    }
}

/// Phase 1 baseline: every wire feature in protocol v1 marked Active.
/// Subsequent protocol versions can layer in `Deprecated` / `Frozen`
/// state via [`FeatureRegistry::extended_with`].
pub fn phase1_baseline() -> FeatureRegistry {
    FeatureRegistry::from_pairs([
        // Identity / envelope (§2 / §3)
        ("envelope.v1", FeatureState::Active),
        ("identity.master_key", FeatureState::Active),
        ("identity.side_key", FeatureState::Active),
        ("linkage_proof.v1", FeatureState::Active),
        // Handshake (§4)
        ("handshake.v1", FeatureState::Active),
        ("handshake.capabilities", FeatureState::Active),
        // Direct messaging (§3.9, §7)
        ("direct.message", FeatureState::Active),
        ("direct.receipt", FeatureState::Active),
        ("direct.typing", FeatureState::Active),
        ("profile.fetch_deliver", FeatureState::Active),
        ("side.retirement", FeatureState::Active),
        // Multi-device pairing (§7.5 — Phase 1.5f)
        ("device.pairing_request", FeatureState::Active),
        ("device.state_bundle", FeatureState::Active),
        ("device.revoke", FeatureState::Active),
        ("device.state_delta", FeatureState::Active),
        // Storage (§5)
        ("storage.get", FeatureState::Active),
        ("storage.have", FeatureState::Active),
        ("storage.miss", FeatureState::Active),
        ("storage.offer", FeatureState::Active),
        ("storage.want", FeatureState::Active),
        ("storage.retract", FeatureState::Active),
        ("storage.preferences", FeatureState::Active),
        // Discovery (§6)
        ("peer.ask_tell", FeatureState::Active),
        ("rendezvous.v1", FeatureState::Active),
        ("forward.store_deliver", FeatureState::Active),
        // Verse (§8 — Phase 1.5)
        ("verse.contract", FeatureState::Active),
        ("verse.join", FeatureState::Active),
        ("verse.leave", FeatureState::Active),
        ("verse.remove", FeatureState::Active),
        ("verse.post", FeatureState::Active),
        ("verse.amend", FeatureState::Active),
        ("verse.reconsent", FeatureState::Active),
        // Public layer (§9 — Phase 2 wire scaffold). The Rust node ships
        // payload codecs but no dispatch handlers; full semantics live
        // in the sidevers.com Laravel registry. Listed here so a
        // capability-negotiating peer can see we speak v1 of each.
        ("public.handle_resolve", FeatureState::Active),
        ("public.handle_attest", FeatureState::Active),
        ("public.page_publish", FeatureState::Active),
        ("public.page_fetch", FeatureState::Active),
        ("public.page_deliver", FeatureState::Active),
        ("public.announcement", FeatureState::Active),
        ("public.directory_entry", FeatureState::Active),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_marks_everything_active() {
        let r = phase1_baseline();
        for (name, state) in r.iter() {
            assert!(
                state.is_active(),
                "phase1 baseline feature {name} should be Active"
            );
            assert!(state.allows_emission());
        }
        assert!(
            r.len() >= 25,
            "baseline should cover all Phase 1 wire features"
        );
    }

    #[test]
    fn extended_with_overrides_baseline() {
        let baseline = phase1_baseline();
        let extended =
            baseline.extended_with([("verse.post", FeatureState::Deprecated { since_version: 2 })]);
        let s = extended.state_of("verse.post").unwrap();
        assert!(s.is_deprecated());
        assert!(s.allows_emission()); // deprecated still allows emission
        // Baseline untouched.
        assert!(baseline.state_of("verse.post").unwrap().is_active());
    }

    #[test]
    fn frozen_forbids_emission_but_still_parses() {
        let frozen = FeatureState::Frozen { since_version: 3 };
        assert!(!frozen.allows_emission());
        assert!(frozen.is_frozen());
        assert!(!frozen.is_active());
        assert!(!frozen.is_deprecated());
    }

    #[test]
    fn unknown_feature_returns_none() {
        let r = phase1_baseline();
        assert!(r.state_of("not.a.feature").is_none());
    }
}
