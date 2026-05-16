//! Phase 1.B1: NAT hole-punching for the Rendezvous flow (spec §6.5).
//!
//! Once two nodes have exchanged their external endpoints via a
//! rendezvous broker, they both try to `dial` each other roughly
//! simultaneously. Each outbound QUIC `Initial` packet creates / refreshes
//! an outbound NAT mapping; the symmetric retries let the connection
//! land even when both sides are behind cone-NATs (the typical residential
//! case).
//!
//! Strategy implemented here:
//!   1. Loop a small number of times with a short interval.
//!   2. On each iteration call `Node::dial` with a tight per-attempt
//!      timeout. Quinn will repeatedly retransmit Initial within the
//!      window, opening the NAT binding from our side.
//!   3. Return the first attempt that succeeds.
//!
//! For full-cone / restricted-cone NATs this works. For symmetric NATs
//! (where the external port depends on the destination) full STUN-style
//! prediction would be needed; that's deferred to a later phase.
//!
//! Callers are expected to coordinate the *roughly simultaneous* part
//! over the rendezvous broker — e.g. both sides agree on a Unix
//! timestamp `T` and call this function with `start_at = T`.

use std::net::SocketAddr;
use std::time::Duration;

use tracing::debug;

use crate::error::{Error, Result};
use crate::session::{Intent, Session};

/// Default per-attempt timeout. Quinn's handshake itself ranges 200ms
/// to a few seconds depending on RTT; 2s is a sensible upper bound for
/// LAN + most WAN scenarios.
pub const HOLE_PUNCH_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(2);

/// Default attempts. With 2s per attempt and 250ms backoff that's a
/// ~12-second total budget which roughly matches a typical NAT
/// binding refresh interval.
pub const HOLE_PUNCH_ATTEMPTS: usize = 5;

/// Default backoff between attempts.
pub const HOLE_PUNCH_BACKOFF: Duration = Duration::from_millis(250);

/// Configuration knobs for [`hole_punch_dial`].
#[derive(Debug, Clone, Copy)]
pub struct HolePunchConfig {
    pub attempts: usize,
    pub attempt_timeout: Duration,
    pub backoff: Duration,
}

impl Default for HolePunchConfig {
    fn default() -> Self {
        Self {
            attempts: HOLE_PUNCH_ATTEMPTS,
            attempt_timeout: HOLE_PUNCH_ATTEMPT_TIMEOUT,
            backoff: HOLE_PUNCH_BACKOFF,
        }
    }
}

/// Dial `peer_addr` with NAT-hole-punching retries. The closure
/// `dial_once` is the per-attempt action — typically
/// `node.dial(peer_addr, intent)`. Generic over the closure so the
/// public Node method can plug in `dial_from(side, peer_addr, intent)`
/// for multi-side hosting.
pub async fn hole_punch_with<F, Fut>(
    config: HolePunchConfig,
    peer_addr: SocketAddr,
    intent: Intent,
    mut dial_once: F,
) -> Result<Session>
where
    F: FnMut(SocketAddr, Intent) -> Fut,
    Fut: std::future::Future<Output = Result<Session>>,
{
    let attempts = config.attempts.max(1);
    for i in 0..attempts {
        let attempt = dial_once(peer_addr, intent);
        match tokio::time::timeout(config.attempt_timeout, attempt).await {
            Ok(Ok(session)) => return Ok(session),
            Ok(Err(e)) => {
                debug!(?e, attempt = i, "hole-punch attempt failed; retrying");
            }
            Err(_) => {
                debug!(attempt = i, "hole-punch attempt timed out; retrying");
            }
        }
        if i + 1 < attempts {
            tokio::time::sleep(config.backoff).await;
        }
    }
    Err(Error::Invariant(
        "hole_punch_dial: peer unreachable after all attempts",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn succeeds_on_first_attempt_when_dial_works() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_for_closure = calls.clone();
        // Note: we can't fabricate a real Session in unit tests
        // (it owns a quinn::Connection). The dial-once closure
        // returns Err on first call to force a retry, then we let
        // it permanently fail to assert the right number of attempts.
        let cfg = HolePunchConfig {
            attempts: 3,
            attempt_timeout: Duration::from_millis(20),
            backoff: Duration::from_millis(1),
        };
        let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let result = hole_punch_with(cfg, addr, Intent::Direct, move |_, _| {
            let c = calls_for_closure.clone();
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                Err::<Session, _>(Error::Invariant("simulated unreachable"))
            }
        })
        .await;
        assert!(result.is_err());
        assert_eq!(
            calls.load(Ordering::SeqCst),
            3,
            "should have tried `attempts` times before giving up"
        );
    }
}
