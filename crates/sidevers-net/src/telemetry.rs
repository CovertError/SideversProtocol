//! Anonymous adoption telemetry.
//!
//! Emits three events from the protocol layer for adoption counting:
//!
//! * `app_started` — every `Node::start()` and every Tauri client launch.
//! * `side_created` — when [`Side::load_or_create`](crate::side::Side::load_or_create)
//!   persists a fresh side row.
//! * `verse_created` — when [`Node::host_verse`](crate::node::Node::host_verse)
//!   registers a new verse.
//!
//! Each event is a single fire-and-forget HTTP POST. The wire payload
//! is exactly:
//!
//! ```json
//! {"event":"verse_created","version":"0.1.3","channel":"stable"}
//! ```
//!
//! No install ID, no side address, no verse address, no peer pubkey,
//! no locale, no timezone — nothing per-instance. Country is derived
//! server-side from the transport IP and the IP discarded; see
//! `TELEMETRY.md` at the repo root for the full data policy.
//!
//! Implementation notes (matching the metrics.rs ethos of "tiny scope,
//! tiny deps"):
//!
//! * Hand-rolled HTTP/1.1 over `tokio::net::TcpStream` — no `reqwest`,
//!   no `hyper`. The payload is fixed-shape and small.
//! * Process-global `OnceLock<Option<mpsc::Sender>>`. `fire()` becomes
//!   a relaxed atomic check + non-blocking `try_send`; overflow drops
//!   silently rather than back-pressuring the caller.
//! * `cfg!(debug_assertions)` short-circuits initialization, so
//!   `cargo test` and `cargo run` (dev builds) never send a packet.
//!   Release builds — what end-users actually run — always do.
//! * No retries, no persistence, no batching. A retry queue or batch
//!   buffer would build a per-instance fingerprint; we explicitly
//!   forgo it.
//! * Failures log at `debug!` and are dropped.

use std::sync::OnceLock;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{Duration, timeout};
use tracing::debug;

/// Default ingest endpoint. Overridable at runtime via the
/// `SIDEVERS_STATS_ENDPOINT` env var (an undocumented escape hatch for
/// local development and integration testing — not a user-facing
/// opt-out).
const DEFAULT_ENDPOINT: &str = "http://stats.sidevers.com/v1/event";

const VERSION: &str = env!("CARGO_PKG_VERSION");

const CHANNEL: &str = if cfg!(debug_assertions) {
    "dev"
} else {
    "stable"
};

/// Per-attempt budgets. Conservative — telemetry must never delay
/// real work. If the network is slow, we drop the event.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Bounded channel between hot-path `fire()` and the background
/// shipper. Burst capacity matches `Metrics`-style hot paths; a flood
/// that exhausts it drops the excess silently.
const CHANNEL_CAPACITY: usize = 16;

/// Process-global handle. `None` means initialization decided to stay
/// disabled (debug build, or empty `SIDEVERS_STATS_ENDPOINT`).
static TX: OnceLock<Option<mpsc::Sender<&'static str>>> = OnceLock::new();

/// Initialize the background shipper. Idempotent; the first call wins
/// and subsequent calls are no-ops. Safe to call from multiple entry
/// points (e.g. both `Node::start` and the Tauri client `setup`).
///
/// In debug builds and when `SIDEVERS_STATS_ENDPOINT` is set to the
/// empty string, this leaves telemetry permanently disabled — `fire`
/// will short-circuit on every call.
pub fn init() {
    TX.get_or_init(|| {
        if cfg!(debug_assertions) {
            return None;
        }
        let endpoint = std::env::var("SIDEVERS_STATS_ENDPOINT")
            .unwrap_or_else(|_| DEFAULT_ENDPOINT.to_owned());
        if endpoint.is_empty() {
            return None;
        }
        let (tx, rx) = mpsc::channel::<&'static str>(CHANNEL_CAPACITY);
        tokio::spawn(shipper(endpoint, rx));
        Some(tx)
    });
}

/// Emit one event. Non-blocking; if the channel is full or telemetry
/// is disabled, the call drops the event silently. Costs one atomic
/// load on the happy path.
pub fn fire(event: &'static str) {
    let Some(slot) = TX.get() else { return };
    let Some(tx) = slot else { return };
    let _ = tx.try_send(event);
}

async fn shipper(endpoint: String, mut rx: mpsc::Receiver<&'static str>) {
    let parsed = match ParsedEndpoint::parse(&endpoint) {
        Some(p) => p,
        None => {
            debug!(%endpoint, "telemetry endpoint unparseable, disabling shipper");
            return;
        }
    };
    while let Some(event) = rx.recv().await {
        if let Err(e) = ship_one(&parsed, event).await {
            debug!(?e, event, "telemetry ship failed");
        }
    }
}

/// Endpoint URL parsed into the three pieces we need for the raw HTTP
/// request line and Host header.
#[derive(Debug, Clone)]
struct ParsedEndpoint {
    host: String,
    port: u16,
    path: String,
}

impl ParsedEndpoint {
    fn parse(url: &str) -> Option<Self> {
        // Strip scheme — we only speak plain HTTP for v1.
        let rest = url.strip_prefix("http://").unwrap_or(url);
        let rest = rest.strip_prefix("https://").unwrap_or(rest);
        let (authority, path_part) = rest.split_once('/').unwrap_or((rest, ""));
        if authority.is_empty() {
            return None;
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_owned(), p.parse().ok()?),
            None => (authority.to_owned(), 80),
        };
        let path = if path_part.is_empty() {
            "/".to_owned()
        } else {
            format!("/{path_part}")
        };
        Some(Self { host, port, path })
    }
}

async fn ship_one(ep: &ParsedEndpoint, event: &'static str) -> std::io::Result<()> {
    let body = format!(r#"{{"event":"{event}","version":"{VERSION}","channel":"{CHANNEL}"}}"#);
    let request = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: sidevers\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        path = ep.path,
        host = ep.host,
        len = body.len(),
    );

    let mut stream = timeout(
        CONNECT_TIMEOUT,
        TcpStream::connect((ep.host.as_str(), ep.port)),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connect"))??;

    timeout(WRITE_TIMEOUT, stream.write_all(request.as_bytes()))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "write"))??;

    // Drain a small amount of the response so the server gets a clean
    // close and our count isn't lost to ECONNRESET. We don't parse it.
    let mut buf = [0u8; 256];
    let _ = timeout(READ_TIMEOUT, stream.read(&mut buf)).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn parse_endpoint_with_path_and_default_port() {
        let p = ParsedEndpoint::parse("http://stats.sidevers.com/v1/event").unwrap();
        assert_eq!(p.host, "stats.sidevers.com");
        assert_eq!(p.port, 80);
        assert_eq!(p.path, "/v1/event");
    }

    #[test]
    fn parse_endpoint_with_explicit_port() {
        let p = ParsedEndpoint::parse("http://127.0.0.1:9999/x").unwrap();
        assert_eq!(p.host, "127.0.0.1");
        assert_eq!(p.port, 9999);
        assert_eq!(p.path, "/x");
    }

    #[test]
    fn parse_endpoint_without_path_defaults_root() {
        let p = ParsedEndpoint::parse("http://localhost:8080").unwrap();
        assert_eq!(p.path, "/");
    }

    #[test]
    fn parse_endpoint_rejects_empty_authority() {
        assert!(ParsedEndpoint::parse("http://").is_none());
    }

    #[tokio::test]
    async fn wire_format_contains_exactly_three_fields() {
        // Stand up a minimal listener that captures one request, then
        // ship one event at it.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let captured = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            // Read until the writer closes; the request fits well
            // under any sane TCP receive window.
            let _ = sock.read_to_end(&mut buf).await;
            buf
        });

        let ep = ParsedEndpoint::parse(&format!("http://{addr}/v1/event")).unwrap();
        ship_one(&ep, "verse_created").await.unwrap();

        let raw = captured.await.unwrap();
        let text = String::from_utf8_lossy(&raw);
        assert!(text.starts_with("POST /v1/event HTTP/1.1\r\n"));
        assert!(text.contains("Content-Type: application/json"));
        assert!(text.contains("\"event\":\"verse_created\""));
        assert!(text.contains("\"version\":\""));
        assert!(text.contains("\"channel\":\""));
        // Privacy invariants: must not contain anything per-instance.
        let lower = text.to_lowercase();
        assert!(!lower.contains("locale"));
        assert!(!lower.contains("country"));
        assert!(!lower.contains("timezone"));
        assert!(!lower.contains("install"));
        assert!(!lower.contains("session"));
        assert!(!lower.contains("authorization"));
        assert!(!lower.contains("cookie"));
        assert!(!lower.contains("accept-language"));
    }

    #[test]
    fn fire_is_noop_when_disabled() {
        // In `cfg(test)`, init() is gated by cfg!(debug_assertions)
        // which is also true under tests — so TX stays None.
        init();
        fire("app_started");
        fire("side_created");
        fire("verse_created");
        // No panic, no hang, no network. That's the entire contract.
    }
}
