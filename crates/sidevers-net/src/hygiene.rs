//! Side hygiene helpers (protocol spec §7.6).
//!
//! §7.6 lays out a small set of operational disciplines to keep two sides
//! of the same person unlinkable in practice. Most of those (independent
//! connections, no cross-side notifications, linkage-is-publication) are
//! already enforced by the handshake / dispatch architecture or are
//! application-layer concerns. The one network-layer helper provided here
//! is **randomized publishing jitter**: "The reference client adds
//! randomized jitter to publishing schedules, so that a side's activity
//! pattern doesn't fingerprint its operator."
//!
//! Usage: `await apply_publish_jitter()` at the start of any outbound
//! publish path (fanout, broadcast, etc.). The default window is
//! `DEFAULT_PUBLISH_JITTER_MS` milliseconds. Tests call
//! `set_jitter_disabled(true)` once at startup to get deterministic
//! timing without manipulating process environment.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use rand::Rng;
use tokio::time;

/// Default jitter window: each publish is delayed by a uniformly-random
/// number of milliseconds in `0..DEFAULT_PUBLISH_JITTER_MS`. Spec §7.6
/// doesn't pin a value; 250ms is short enough to feel responsive but
/// breaks trivial side-by-side timing correlation.
pub const DEFAULT_PUBLISH_JITTER_MS: u64 = 250;

/// Global jitter kill-switch. Read by `apply_jitter_ms`; flipped by
/// `set_jitter_disabled`. Process-wide; intended for the conformance
/// harness to disable jitter once during test setup.
static JITTER_DISABLED: AtomicBool = AtomicBool::new(false);

/// Disable (or re-enable) publish jitter for the rest of the process.
/// Use sparingly — the only intended caller is the conformance harness,
/// which sets it `true` once at module-init time.
pub fn set_jitter_disabled(disabled: bool) {
    JITTER_DISABLED.store(disabled, Ordering::Relaxed);
}

/// True iff jitter has been disabled via `set_jitter_disabled`.
pub fn is_jitter_disabled() -> bool {
    JITTER_DISABLED.load(Ordering::Relaxed)
}

/// Sleep for a uniformly-random duration in `0..DEFAULT_PUBLISH_JITTER_MS`.
/// Returns immediately if `set_jitter_disabled(true)` has been called.
pub async fn apply_publish_jitter() {
    apply_jitter_ms(DEFAULT_PUBLISH_JITTER_MS).await
}

/// Like `apply_publish_jitter` but with a caller-chosen upper bound.
/// `max_ms == 0` is a no-op; the global kill-switch also short-circuits.
pub async fn apply_jitter_ms(max_ms: u64) {
    if max_ms == 0 || is_jitter_disabled() {
        return;
    }
    let pick = rand::thread_rng().gen_range(0..max_ms);
    time::sleep(Duration::from_millis(pick)).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[tokio::test]
    async fn zero_max_returns_immediately() {
        let start = Instant::now();
        apply_jitter_ms(0).await;
        assert!(start.elapsed() < Duration::from_millis(5));
    }

    #[tokio::test]
    async fn small_jitter_is_bounded() {
        // 50ms ceiling — sleeps at most 49ms. Generous upper bound on the
        // total wall-clock for scheduling latency.
        let start = Instant::now();
        apply_jitter_ms(50).await;
        assert!(
            start.elapsed() < Duration::from_millis(200),
            "jitter exceeded bound: {:?}",
            start.elapsed()
        );
    }

    #[tokio::test]
    async fn kill_switch_short_circuits() {
        set_jitter_disabled(true);
        let start = Instant::now();
        apply_jitter_ms(500).await;
        let elapsed = start.elapsed();
        set_jitter_disabled(false);
        assert!(
            elapsed < Duration::from_millis(20),
            "expected near-zero delay with kill-switch on, got {elapsed:?}"
        );
    }
}
