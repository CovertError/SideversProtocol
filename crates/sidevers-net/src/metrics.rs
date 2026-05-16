//! Phase 1.H3: counters + Prometheus-format /metrics endpoint.
//!
//! `Metrics` is a cheap `Arc<...>` of atomic counters threaded through
//! `Services`. Hot paths (envelope-ingest gates, handshake refusals,
//! delivery channels) increment them. `serve_on(addr)` spawns a tiny
//! Tokio TCP loop that answers any `GET /metrics` with the current
//! values in [Prometheus text exposition format].
//!
//! Why hand-rolled instead of an off-the-shelf crate: keeps the
//! dependency surface small (no hyper / no prometheus crate, both of
//! which pull in 20+ transitive deps) and we only need to emit, not
//! parse. The exposition format is a few lines of text.
//!
//! [Prometheus text exposition format]: https://prometheus.io/docs/instrumenting/exposition_formats/

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

#[derive(Debug, Default)]
struct Inner {
    envelopes_total: AtomicU64,
    envelopes_dropped_reputation: AtomicU64,
    envelopes_dropped_freshness: AtomicU64,
    envelopes_dropped_replay: AtomicU64,
    envelopes_dropped_skew_hard: AtomicU64,
    envelopes_warned_skew_soft: AtomicU64,
    handshake_throttled_total: AtomicU64,
    dms_received_total: AtomicU64,
    broadcasts_received_total: AtomicU64,
    verse_posts_received_total: AtomicU64,
    linkage_proofs_received_total: AtomicU64,
    forward_deliver_retries_total: AtomicU64,
    storage_retract_ignored_total: AtomicU64,
    storage_objects_evicted_total: AtomicU64,
}

/// Cheap, clonable counter handle. Every increment is a relaxed atomic
/// add — safe to call from hot paths.
#[derive(Debug, Clone, Default)]
pub struct Metrics {
    inner: Arc<Inner>,
}

impl Metrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn incr_envelope(&self) {
        self.inner.envelopes_total.fetch_add(1, Ordering::Relaxed);
    }
    pub fn incr_dropped_reputation(&self) {
        self.inner
            .envelopes_dropped_reputation
            .fetch_add(1, Ordering::Relaxed);
    }
    pub fn incr_dropped_freshness(&self) {
        self.inner
            .envelopes_dropped_freshness
            .fetch_add(1, Ordering::Relaxed);
    }
    pub fn incr_dropped_replay(&self) {
        self.inner
            .envelopes_dropped_replay
            .fetch_add(1, Ordering::Relaxed);
    }
    pub fn incr_dropped_skew_hard(&self) {
        self.inner
            .envelopes_dropped_skew_hard
            .fetch_add(1, Ordering::Relaxed);
    }
    pub fn incr_warned_skew_soft(&self) {
        self.inner
            .envelopes_warned_skew_soft
            .fetch_add(1, Ordering::Relaxed);
    }
    pub fn incr_handshake_throttled(&self) {
        self.inner
            .handshake_throttled_total
            .fetch_add(1, Ordering::Relaxed);
    }
    pub fn incr_dm_received(&self) {
        self.inner
            .dms_received_total
            .fetch_add(1, Ordering::Relaxed);
    }
    pub fn incr_broadcast_received(&self) {
        self.inner
            .broadcasts_received_total
            .fetch_add(1, Ordering::Relaxed);
    }
    pub fn incr_verse_post_received(&self) {
        self.inner
            .verse_posts_received_total
            .fetch_add(1, Ordering::Relaxed);
    }
    pub fn incr_linkage_proof_received(&self) {
        self.inner
            .linkage_proofs_received_total
            .fetch_add(1, Ordering::Relaxed);
    }
    pub fn incr_forward_retry(&self) {
        self.inner
            .forward_deliver_retries_total
            .fetch_add(1, Ordering::Relaxed);
    }
    pub fn incr_storage_retract_ignored(&self) {
        self.inner
            .storage_retract_ignored_total
            .fetch_add(1, Ordering::Relaxed);
    }
    pub fn incr_storage_object_evicted(&self, n: u64) {
        self.inner
            .storage_objects_evicted_total
            .fetch_add(n, Ordering::Relaxed);
    }

    /// Render the current snapshot in Prometheus text exposition format.
    /// Each counter gets a `# HELP` line, a `# TYPE counter` line, then
    /// the value.
    pub fn render_prometheus(&self) -> String {
        let i = &self.inner;
        let load = |a: &AtomicU64| a.load(Ordering::Relaxed);
        let mut s = String::with_capacity(2048);
        let entries: &[(&str, &str, u64)] = &[
            (
                "sidevers_envelopes_total",
                "Total inbound envelopes (before any gate).",
                load(&i.envelopes_total),
            ),
            (
                "sidevers_envelopes_dropped_reputation_total",
                "Envelopes dropped by reputation/rate-limit gate.",
                load(&i.envelopes_dropped_reputation),
            ),
            (
                "sidevers_envelopes_dropped_freshness_total",
                "Envelopes dropped by freshness check.",
                load(&i.envelopes_dropped_freshness),
            ),
            (
                "sidevers_envelopes_dropped_replay_total",
                "Envelopes dropped by replay-cache match.",
                load(&i.envelopes_dropped_replay),
            ),
            (
                "sidevers_envelopes_dropped_skew_hard_total",
                "Envelopes dropped for exceeding SOFT_MAX_SKEW_SECS.",
                load(&i.envelopes_dropped_skew_hard),
            ),
            (
                "sidevers_envelopes_warned_skew_soft_total",
                "Envelopes accepted in soft-skew band (DEFAULT < skew <= SOFT).",
                load(&i.envelopes_warned_skew_soft),
            ),
            (
                "sidevers_handshake_throttled_total",
                "Handshake attempts refused by per-source rate limit.",
                load(&i.handshake_throttled_total),
            ),
            (
                "sidevers_dms_received_total",
                "Direct messages successfully delivered to the inbox channel.",
                load(&i.dms_received_total),
            ),
            (
                "sidevers_broadcasts_received_total",
                "Public broadcasts successfully delivered to the gossip channel.",
                load(&i.broadcasts_received_total),
            ),
            (
                "sidevers_verse_posts_received_total",
                "Verse posts successfully delivered to the verse channel.",
                load(&i.verse_posts_received_total),
            ),
            (
                "sidevers_linkage_proofs_received_total",
                "Linkage proofs successfully delivered to the linkage channel.",
                load(&i.linkage_proofs_received_total),
            ),
            (
                "sidevers_forward_deliver_retries_total",
                "Times a held message was re-stored after a transient send failure.",
                load(&i.forward_deliver_retries_total),
            ),
            (
                "sidevers_storage_retract_ignored_total",
                "STORAGE_RETRACT envelopes dropped because the sender wasn't a recorded publisher.",
                load(&i.storage_retract_ignored_total),
            ),
            (
                "sidevers_storage_objects_evicted_total",
                "Object-store evictions performed by the LRU policy.",
                load(&i.storage_objects_evicted_total),
            ),
        ];
        for (name, help, value) in entries {
            s.push_str(&format!("# HELP {name} {help}\n"));
            s.push_str(&format!("# TYPE {name} counter\n"));
            s.push_str(&format!("{name} {value}\n"));
        }
        s
    }

    /// Bind a tiny HTTP responder on `addr` that answers every GET
    /// with the current metrics snapshot. Returns the bound address
    /// (useful for `:0` ephemeral binds) and a JoinHandle for the
    /// listener task. Stop by aborting the handle or dropping the
    /// task.
    ///
    /// # Security
    /// The endpoint serves **counter values without authentication or
    /// TLS**. These counters reveal operationally-sensitive info —
    /// peer pubkeys that have spoken to this node and at what rate.
    /// Binding to a public interface (e.g. `0.0.0.0:9090`) exposes
    /// that information to the internet. For most deployments,
    /// **prefer [`serve_on_local`](Self::serve_on_local)**, which
    /// constrains the bind to `127.0.0.1`. Use `serve_on` only when
    /// you've placed the node behind an external firewall or reverse
    /// proxy that handles auth.
    pub async fn serve_on(
        &self,
        addr: SocketAddr,
    ) -> std::io::Result<(SocketAddr, JoinHandle<()>)> {
        let listener = TcpListener::bind(addr).await?;
        let bound = listener.local_addr()?;
        let metrics = self.clone();
        let handle = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((mut stream, _peer)) => {
                        let metrics = metrics.clone();
                        tokio::spawn(async move {
                            // Drain the (small) request — we don't parse it,
                            // every GET gets the same answer.
                            let mut buf = [0u8; 1024];
                            let _ = stream.read(&mut buf).await;
                            let body = metrics.render_prometheus();
                            let response = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                body.len(),
                                body
                            );
                            if let Err(e) = stream.write_all(response.as_bytes()).await {
                                debug!("metrics writer: {e}");
                            }
                            let _ = stream.shutdown().await;
                        });
                    }
                    Err(e) => {
                        warn!("metrics listener accept failed: {e}");
                        break;
                    }
                }
            }
        });
        Ok((bound, handle))
    }

    /// Phase 1.H3 (audit-pass M2): bind the metrics endpoint to
    /// `127.0.0.1` only, so a misconfigured operator can't
    /// accidentally publish counters to the internet. Pass `0` for
    /// the port to get an ephemeral free port.
    ///
    /// Prefer this over [`serve_on`](Self::serve_on) for any
    /// deployment that doesn't sit behind an external firewall.
    pub async fn serve_on_local(&self, port: u16) -> std::io::Result<(SocketAddr, JoinHandle<()>)> {
        let addr: SocketAddr = (std::net::Ipv4Addr::LOCALHOST, port).into();
        self.serve_on(addr).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_includes_all_counters_with_zero_baseline() {
        let m = Metrics::new();
        let s = m.render_prometheus();
        assert!(s.contains("sidevers_envelopes_total 0"));
        assert!(s.contains("sidevers_handshake_throttled_total 0"));
        assert!(s.contains("# TYPE sidevers_envelopes_total counter"));
    }

    #[test]
    fn increments_show_up_in_render() {
        let m = Metrics::new();
        m.incr_envelope();
        m.incr_envelope();
        m.incr_dropped_replay();
        let s = m.render_prometheus();
        assert!(s.contains("sidevers_envelopes_total 2"));
        assert!(s.contains("sidevers_envelopes_dropped_replay_total 1"));
    }

    #[tokio::test]
    async fn http_endpoint_serves_text_exposition() {
        let m = Metrics::new();
        m.incr_envelope();
        let (addr, handle) = m.serve_on("127.0.0.1:0".parse().unwrap()).await.unwrap();

        // Round-trip a GET.
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET /metrics HTTP/1.0\r\n\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let resp = String::from_utf8_lossy(&buf);
        assert!(resp.starts_with("HTTP/1.1 200 OK"));
        assert!(resp.contains("sidevers_envelopes_total 1"));
        handle.abort();
    }
}
