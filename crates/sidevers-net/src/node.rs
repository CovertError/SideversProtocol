//! Top-level node glue: accepts incoming connections, runs the responder
//! handshake, dispatches by intent. Also offers a `dial` method that runs
//! the initiator handshake and returns a `Session`.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;

use sidevers_core::Envelope;
use sidevers_core::envelope::{NONCE_LEN, now_unix_seconds, random_nonce};
use sidevers_core::keys::SideKey;
use sidevers_core::linkage::LinkageProof;
use sidevers_core::messages::device::{
    DeltaOp, DeviceRevokePayload, PairingQr, PairingRequestPayload, RelationshipRecord,
    STATE_BUNDLE_AAD, StateBundleInner, StateBundlePayload, StateDeltaPayload,
};
use sidevers_core::messages::forward::{ForwardDeliverPayload, ForwardStorePayload};
use sidevers_core::messages::peer::{PeerAskPayload, PeerInfo, PeerTellPayload};
use sidevers_core::messages::profile::{self as profile_msg, ProfilePayload};
use sidevers_core::messages::rendezvous::{RendezvousAckPayload, RendezvousPayload};
use sidevers_core::messages::retirement::SideRetirementPayload;
use sidevers_core::messages::verse::{
    ContractDeliverPayload, ContractFetchPayload, DataDisposition, FieldValues, JoinAcceptPayload,
    JoinDeclinePayload, JoinRequestPayload, VerseLeavePayload, VersePostPayload,
    VerseReconsentPayload, VerseRemovePayload,
};
use sidevers_core::payload as core_payload;
use sidevers_core::replay::{DEFAULT_TTL_SECS, ReplayCache};
use sidevers_core::verse::{ContractObject, MembershipToken, VerseContentKey};
use sidevers_core::{Address, AddressKind, LogId, MessageType};
use sidevers_storage::ObjectStore;
use sidevers_storage::object::ADDRESS_LEN;
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use crate::connection_pool::ConnectionPool;
use crate::error::{Error, Result};
use crate::forward::Mailbox;
use crate::framing::{recv_envelope, send_envelope};
use crate::gossip::GossipState;
use crate::gossip_policy::{GossipPolicy, GossipPropagation};
use crate::handshake::{run_initiator, run_responder};
use crate::handshake_limit::HandshakeLimiter;
use crate::hygiene::apply_publish_jitter;
use crate::metrics::Metrics;
use crate::peers::{PeerTable, unix_now};
use crate::provenance::PublisherTable;
use crate::relationships::{SideLifecycle, SideRelationship};
use crate::replay_journal::SqliteReplayJournal;
use crate::reputation::ReputationTable;
use crate::session::{Intent, Session};
use crate::side::Side;
use crate::side_store::SideStore;
use crate::storage_protocol::{
    StorageGetPayload, StorageHavePayload, StorageMissPayload, StorageRetractPayload,
    StorageWantPayload,
};
use crate::transport::build_server_endpoint;
use crate::verse::VerseHost;

#[derive(Debug, Clone)]
pub struct DirectMessageReceived {
    pub envelope: Envelope,
    pub plaintext: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct VersePostReceived {
    pub envelope: Envelope,
    pub plaintext: Vec<u8>,
}

/// A signed `ProfilePayload` delivered to this node in response to a
/// `PROFILE_FETCH`. Spec §7.3.
#[derive(Debug, Clone)]
pub struct ProfileDelivered {
    pub envelope: Envelope,
    pub profile: ProfilePayload,
}

/// A `LINKAGE_PUBLISH` envelope received and verified (both signatures
/// good). Spec §2.7. The accompanying `LinkageProof` is structurally
/// valid; consumers can decide independently whether to trust the link
/// (the cryptographic fact "side_a and side_b both signed this" is all
/// the protocol guarantees).
#[derive(Debug, Clone)]
pub struct LinkageProofReceived {
    pub envelope: Envelope,
    pub proof: LinkageProof,
}

/// Per-node services threaded through the accept loop and handlers.
#[derive(Clone)]
struct Services {
    /// The hosted side's keypair. Equivalent to `side_state.keypair_arc()`,
    /// kept as a direct field for the many handlers that just sign with it.
    side: Arc<SideKey>,
    /// Full per-side state (profile, retired-seen, relationships, lifecycle,
    /// co-holders) — Phase 1.5f, Track A. Persistence (SQLite) is wired
    /// transparently through `Side`'s mutators.
    side_state: Arc<Side>,
    store: ObjectStore,
    replay: Arc<Mutex<ReplayCache>>,
    peers: PeerTable,
    mailbox: Mailbox,
    gossip: GossipState,
    /// Currently-active inbound gossip sessions — used to fan novel
    /// broadcasts out to subscribers. Keyed on the peer's side public key.
    active_gossip: Arc<Mutex<HashMap<[u8; 32], quinn::Connection>>>,
    /// Phase 1.5.E: every verse this node hosts, keyed by verse address.
    /// Pre-1.5.E was `Option<VerseHost>` (one per node); now a Node can
    /// host multiple verses simultaneously and dispatch routes by the
    /// verse address embedded in the incoming envelope's payload.
    hosted_verses: Arc<Mutex<HashMap<[u8; 32], VerseHost>>>,
    /// Per-peer reputation + token-bucket rate limit (spec §6.9). Consulted
    /// at envelope-entry on every inbound; misbehaving peers get
    /// envelopes silently dropped before any per-envelope work.
    reputation: ReputationTable,
    /// Per-source-IP handshake rate limiter (spec §4.6). Consulted at
    /// QUIC accept; sources over budget get their connection closed
    /// without running the responder handshake, sparing CPU + entropy.
    handshake_limit: HandshakeLimiter,
    /// Per-object publisher set (Phase 1.C3, spec §5.6). Tracks which
    /// peers have offered each content-addressed object so a subsequent
    /// STORAGE_RETRACT can only narrow the publisher list, not drop an
    /// object that other publishers still back.
    provenance: PublisherTable,
    /// Gossip-fanout policy (Phase 1.A3, spec §6.9.3). Consulted in
    /// `fanout_broadcast` to decide which currently-connected peers
    /// should receive a relayed broadcast. Default `Open` matches
    /// pre-1.A3 behavior; an operator can tighten via
    /// `Node::set_gossip_policy`.
    gossip_policy: Arc<Mutex<GossipPolicy>>,
    /// Phase 1.H3: process-wide counters surfaced over the optional
    /// Prometheus `/metrics` endpoint.
    metrics: Metrics,
    dm_tx: mpsc::Sender<DirectMessageReceived>,
    gossip_tx: mpsc::Sender<Envelope>,
    verse_post_tx: mpsc::Sender<VersePostReceived>,
    profile_tx: mpsc::Sender<ProfileDelivered>,
    linkage_tx: mpsc::Sender<LinkageProofReceived>,
}

pub struct Node {
    endpoint: quinn::Endpoint,
    services: Services,
    listen_addr: SocketAddr,
    /// Phase 1.H4 connection pool — `dial_pooled` reuses an alive
    /// `quinn::Connection` to a peer instead of paying the full TLS +
    /// QUIC handshake every time. Keyed on `(peer_addr, source_side)`.
    pool: ConnectionPool,
    /// Per-side SQLite store, shared with every secondary side added via
    /// `add_side`. Phase 1.5f Track A.
    side_store: SideStore,
    /// Additional sides hosted by this Node (Phase 1.5f Track B). Each
    /// has its own QUIC endpoint and accept loop; cross-side traffic is
    /// strictly separated per spec §7.6.
    extras: Arc<Mutex<Vec<HostedSide>>>,
    dm_rx: Mutex<mpsc::Receiver<DirectMessageReceived>>,
    gossip_rx: Mutex<mpsc::Receiver<Envelope>>,
    verse_post_rx: Mutex<mpsc::Receiver<VersePostReceived>>,
    profile_rx: Mutex<mpsc::Receiver<ProfileDelivered>>,
    linkage_rx: Mutex<mpsc::Receiver<LinkageProofReceived>>,
    accept_handle: JoinHandle<()>,
}

/// Internal record of one extra (non-primary) side hosted on this Node.
/// Phase 1.5f Track B: each extra side runs on its own QUIC endpoint so
/// no two sides multiplex over the same connection (spec §7.6).
struct HostedSide {
    side: Arc<Side>,
    endpoint: quinn::Endpoint,
    listen_addr: SocketAddr,
    accept_handle: JoinHandle<()>,
}

impl Node {
    /// Start a node bound at `listen_addr`. Returns once the QUIC endpoint
    /// is listening and the accept loop is spawned.
    pub async fn start(side: SideKey, listen_addr: SocketAddr, data_dir: &Path) -> Result<Self> {
        let endpoint = build_server_endpoint(listen_addr)?;
        let local = endpoint.local_addr()?;
        let store = ObjectStore::open(data_dir).await?;
        let side_store = SideStore::open(data_dir).await?;
        let label = Some(side.label().as_str().to_owned());
        let side_obj = Arc::new(Side::load_or_create(side, label, side_store.clone()).await?);
        let side_arc = side_obj.keypair_arc();

        // Phase 1.E: replay cache is bounded + persisted. Open the SQLite
        // journal alongside the side store, drain still-fresh entries
        // into the in-memory cache, then attach the journal so future
        // observations are recorded durably. A restart inside the TTL
        // window therefore still detects a replayed envelope.
        let journal = Arc::new(SqliteReplayJournal::open(data_dir)?);
        let now = now_unix_seconds().map_err(Error::Core)?;
        let preload_entries = journal
            .load_active(now, DEFAULT_TTL_SECS)
            .unwrap_or_default();
        let mut cache = ReplayCache::new();
        cache.preload(now, preload_entries);
        cache.set_journal(journal);
        let replay = Arc::new(Mutex::new(cache));
        let peers = PeerTable::default();
        let mailbox = Mailbox::new();
        let gossip = GossipState::new();

        let (dm_tx, dm_rx) = mpsc::channel::<DirectMessageReceived>(128);
        let (gossip_tx, gossip_rx) = mpsc::channel::<Envelope>(128);
        let (verse_post_tx, verse_post_rx) = mpsc::channel::<VersePostReceived>(128);
        let (profile_tx, profile_rx) = mpsc::channel::<ProfileDelivered>(32);
        let (linkage_tx, linkage_rx) = mpsc::channel::<LinkageProofReceived>(32);

        let services = Services {
            side: side_arc,
            side_state: side_obj,
            store,
            replay,
            peers,
            mailbox,
            gossip,
            active_gossip: Arc::new(Mutex::new(HashMap::new())),
            hosted_verses: Arc::new(Mutex::new(HashMap::new())),
            reputation: ReputationTable::default(),
            handshake_limit: HandshakeLimiter::default(),
            provenance: PublisherTable::new(),
            gossip_policy: Arc::new(Mutex::new(GossipPolicy::default())),
            metrics: Metrics::new(),
            dm_tx,
            gossip_tx,
            verse_post_tx,
            profile_tx,
            linkage_tx,
        };

        let accept_handle = tokio::spawn(accept_loop(endpoint.clone(), services.clone()));

        Ok(Self {
            endpoint,
            services,
            listen_addr: local,
            pool: ConnectionPool::new(),
            side_store,
            extras: Arc::new(Mutex::new(Vec::new())),
            dm_rx: Mutex::new(dm_rx),
            gossip_rx: Mutex::new(gossip_rx),
            verse_post_rx: Mutex::new(verse_post_rx),
            profile_rx: Mutex::new(profile_rx),
            linkage_rx: Mutex::new(linkage_rx),
            accept_handle,
        })
    }

    /// Add a secondary hosted side to this Node, listening on its own
    /// QUIC endpoint (spec §7.6: "A node running two sides MUST NOT
    /// multiplex their traffic over a single QUIC connection."). Returns
    /// the `Arc<Side>` plus the side's bound listen address.
    ///
    /// The new side shares the Node's object store, peer table, mailbox,
    /// gossip dedup, and inbound channels (dm_tx, gossip_tx, etc.) so a
    /// caller draining `next_direct_message` sees DMs for all hosted
    /// sides on this Node, tagged by `envelope.to`.
    pub async fn add_side(
        &self,
        side: SideKey,
        listen_addr: SocketAddr,
    ) -> Result<(Arc<Side>, SocketAddr)> {
        let endpoint = build_server_endpoint(listen_addr)?;
        let local = endpoint.local_addr()?;
        let label = Some(side.label().as_str().to_owned());
        let side_obj = Arc::new(Side::load_or_create(side, label, self.side_store.clone()).await?);
        let side_arc = side_obj.keypair_arc();

        let services = Services {
            side: side_arc,
            side_state: side_obj.clone(),
            store: self.services.store.clone(),
            replay: Arc::new(Mutex::new(ReplayCache::new())),
            peers: self.services.peers.clone(),
            mailbox: self.services.mailbox.clone(),
            gossip: self.services.gossip.clone(),
            active_gossip: Arc::new(Mutex::new(HashMap::new())),
            // Extra sides on the same node still host independent
            // verses; the secondary endpoint accepts Verse-intent for
            // any verse the operator registers on it via `host_verse`.
            hosted_verses: Arc::new(Mutex::new(HashMap::new())),
            reputation: self.services.reputation.clone(),
            handshake_limit: self.services.handshake_limit.clone(),
            provenance: self.services.provenance.clone(),
            gossip_policy: self.services.gossip_policy.clone(),
            metrics: self.services.metrics.clone(),
            dm_tx: self.services.dm_tx.clone(),
            linkage_tx: self.services.linkage_tx.clone(),
            gossip_tx: self.services.gossip_tx.clone(),
            verse_post_tx: self.services.verse_post_tx.clone(),
            profile_tx: self.services.profile_tx.clone(),
        };

        let accept_handle = tokio::spawn(accept_loop(endpoint.clone(), services));
        self.extras.lock().await.push(HostedSide {
            side: side_obj.clone(),
            endpoint,
            listen_addr: local,
            accept_handle,
        });
        Ok((side_obj, local))
    }

    /// Snapshot all sides hosted on this Node (primary + secondaries).
    pub async fn sides(&self) -> Vec<Arc<Side>> {
        let mut out = vec![self.services.side_state.clone()];
        for s in self.extras.lock().await.iter() {
            out.push(s.side.clone());
        }
        out
    }

    /// Look up a hosted side by its public address. Returns `None` if not
    /// hosted on this Node.
    pub async fn side_by_address(&self, address: &[u8; 32]) -> Option<Arc<Side>> {
        if &self.services.side.public_bytes() == address {
            return Some(self.services.side_state.clone());
        }
        for s in self.extras.lock().await.iter() {
            if &s.side.address == address {
                return Some(s.side.clone());
            }
        }
        None
    }

    /// Return the listen address of the hosted side with the given pubkey
    /// (primary or secondary), or `None` if not hosted.
    pub async fn side_listen_addr(&self, address: &[u8; 32]) -> Option<SocketAddr> {
        if &self.services.side.public_bytes() == address {
            return Some(self.listen_addr);
        }
        for s in self.extras.lock().await.iter() {
            if &s.side.address == address {
                return Some(s.listen_addr);
            }
        }
        None
    }

    /// Phase 1.H4: like [`dial`](Self::dial) but reuses a cached
    /// `quinn::Connection` to `peer_addr` (from the primary side) if
    /// one is still alive. Falls back to a fresh dial otherwise. Cuts
    /// the per-call cost of repeated peer interactions to just the
    /// inner Sidevers handshake.
    pub async fn dial_pooled(&self, peer_addr: SocketAddr, intent: Intent) -> Result<Session> {
        let side_pk = self.services.side.public_bytes();
        if let Some(conn) = self.pool.get(peer_addr, &side_pk).await {
            // Run a fresh inner handshake on the cached transport. If
            // the protocol handshake itself fails, the connection is
            // likely dead — drop from the pool and retry once via
            // `dial`.
            match run_initiator(&conn, &self.services.side, intent, None).await {
                Ok(session) => {
                    self.services
                        .peers
                        .insert(PeerInfo {
                            address: session.peer_side,
                            intents: vec![intent.as_u8()],
                            endpoints: vec![peer_addr.to_string()],
                            last_seen: unix_now(),
                        })
                        .await;
                    return Ok(session);
                }
                Err(e) => {
                    debug!(
                        ?e,
                        "dial_pooled: handshake on cached connection failed; falling back to fresh dial"
                    );
                    self.pool.invalidate(peer_addr, &side_pk).await;
                }
            }
        }
        self.dial(peer_addr, intent).await
    }

    /// Handle to the QUIC connection pool (Phase 1.H4). Tests inspect
    /// `len()` to confirm reuse; ops can `clear()` to force a fresh
    /// transport on next dial.
    pub fn connection_pool(&self) -> ConnectionPool {
        self.pool.clone()
    }

    /// Phase 1.B1: NAT-hole-punching dial. Retries `Node::dial` up to
    /// `config.attempts` times with a tight per-attempt timeout. Each
    /// attempt sends fresh QUIC Initial packets which open / refresh
    /// the outbound NAT mapping; if the peer is also dialing back
    /// (coordinated via the rendezvous broker), one attempt lands.
    ///
    /// For full-cone / restricted-cone NATs this works. Symmetric NATs
    /// would need STUN-style port prediction (deferred).
    pub async fn hole_punch_dial(
        &self,
        peer_addr: SocketAddr,
        intent: Intent,
        config: crate::hole_punch::HolePunchConfig,
    ) -> Result<Session> {
        crate::hole_punch::hole_punch_with(config, peer_addr, intent, |addr, intent| async move {
            self.dial(addr, intent).await
        })
        .await
    }

    /// Like [`dial`](Self::dial) but uses a specific hosted side (primary or
    /// secondary) as the local identity. Each hosted side runs on its own
    /// QUIC endpoint per spec §7.6 — this dials out via that side's
    /// endpoint so the peer sees the right source address and pubkey.
    pub async fn dial_from(
        &self,
        side_addr: &[u8; 32],
        peer_addr: SocketAddr,
        intent: Intent,
    ) -> Result<Session> {
        // Primary side reuses the node-level endpoint.
        if &self.services.side.public_bytes() == side_addr {
            return self.dial(peer_addr, intent).await;
        }
        let (side_key, endpoint) = {
            let extras = self.extras.lock().await;
            let h = extras
                .iter()
                .find(|h| &h.side.address == side_addr)
                .ok_or(Error::Invariant("dial_from: side not hosted"))?;
            (h.side.keypair_arc(), h.endpoint.clone())
        };
        let connecting = endpoint.connect(peer_addr, "sidevers")?;
        let conn = connecting.await?;
        let session = run_initiator(&conn, &side_key, intent, None).await?;
        self.services
            .peers
            .insert(PeerInfo {
                address: session.peer_side,
                intents: vec![intent.as_u8()],
                endpoints: vec![peer_addr.to_string()],
                last_seen: unix_now(),
            })
            .await;
        Ok(session)
    }

    // -----------------------------------------------------------------
    // Multi-device pairing (§7.5) — Phase 1.5f Track C
    // -----------------------------------------------------------------

    /// Generate a fresh QR for pairing a new device with the side at
    /// `side_addr` (must be hosted on this Node). Records a one-time
    /// nonce on that side; the new device proves it scanned the QR by
    /// including the nonce in its `PairingRequest`.
    pub async fn generate_pairing_qr(&self, side_addr: &[u8; 32]) -> Result<PairingQr> {
        let side = self
            .side_by_address(side_addr)
            .await
            .ok_or(Error::Invariant("generate_pairing_qr: side not hosted"))?;
        let listen = self
            .side_listen_addr(side_addr)
            .await
            .ok_or(Error::Invariant(
                "generate_pairing_qr: side has no endpoint",
            ))?;
        // PAIRING_NONCE_LEN == 16 matches the protocol's envelope nonce
        // size, so we can reuse `random_nonce` for the QR nonce too.
        let nonce = random_nonce()?;
        side.add_pending_pairing(nonce).await;
        Ok(PairingQr {
            side: *side_addr,
            nonce,
            dial_addr: listen.to_string(),
        })
    }

    /// New-device entrypoint: dial the QR's address, exchange
    /// PAIRING_REQUEST / STATE_BUNDLE, install the side locally. The
    /// returned `Arc<Side>` is now hosted on this Node on its own
    /// endpoint.
    ///
    /// # Errors
    /// - `Error::Invariant` for malformed QR, mismatched recipient
    ///   pubkey, mismatched pairing nonce, or bundle that decrypts to a
    ///   side seed not matching `qr.side`.
    /// - Bundle wait times out after 10 s if the existing device never
    ///   responds.
    /// - Underlying `quinn` / `Core` errors via `From`.
    #[tracing::instrument(
        name = "pairing.accept",
        skip(self, qr),
        fields(side = %LogId::new(&qr.side), dial_addr = %qr.dial_addr),
        err
    )]
    pub async fn accept_pairing(&self, qr: PairingQr) -> Result<(Arc<Side>, SocketAddr)> {
        // 1. Generate a fresh ephemeral device key (Ed25519).
        let ephemeral_master = sidevers_core::keys::MasterKey::generate().map_err(Error::Core)?;
        let device_key = ephemeral_master
            .derive_side(&"pairing".into())
            .map_err(Error::Core)?;
        drop(ephemeral_master);

        // 2. Dial the existing device.
        let peer_addr: SocketAddr = qr
            .dial_addr
            .parse()
            .map_err(|_| Error::Invariant("accept_pairing: bad dial address"))?;
        let connecting = self.endpoint.connect(peer_addr, "sidevers")?;
        let conn = connecting.await?;
        let session = run_initiator(&conn, &device_key, Intent::Direct, None).await?;

        // 3. Send PAIRING_REQUEST on a fresh bidi stream.
        let device_pubkey = device_key.public_bytes();
        let req = PairingRequestPayload::sign(qr.side, &device_key, device_pubkey, qr.nonce)
            .map_err(Error::Core)?;
        let req_env = Envelope::sign_with(
            MessageType::DEVICE_PAIRING_REQUEST,
            &device_key,
            Some(qr.side),
            req.to_wire_bytes(),
            sidevers_core::envelope::now_unix_seconds().map_err(Error::Core)?,
            random_nonce()?,
        )
        .map_err(Error::Core)?;
        let (mut send, mut recv) = session.open_and_send(&req_env).await?;
        send.finish().ok();

        // 4. Await STATE_BUNDLE on the same stream (10-second timeout).
        let resp =
            tokio::time::timeout(std::time::Duration::from_secs(10), recv_envelope(&mut recv))
                .await
                .map_err(|_| Error::Invariant("accept_pairing: bundle wait timeout"))??;
        if resp.message_type != MessageType::DEVICE_STATE_BUNDLE {
            return Err(Error::Invariant(
                "accept_pairing: expected DEVICE_STATE_BUNDLE",
            ));
        }
        let bundle = StateBundlePayload::from_wire_bytes(&resp.payload).map_err(Error::Core)?;

        // 5. Binding checks.
        if bundle.side != qr.side {
            return Err(Error::Invariant("accept_pairing: bundle.side != qr.side"));
        }
        if bundle.recipient_device != device_pubkey {
            return Err(Error::Invariant("accept_pairing: recipient mismatch"));
        }
        if bundle.nonce != qr.nonce {
            return Err(Error::Invariant("accept_pairing: nonce mismatch"));
        }

        // 6. Decrypt.
        let inner_bytes = core_payload::open(
            &bundle.sealed_state,
            &device_key,
            &qr.side,
            &bundle.key_nonce,
            STATE_BUNDLE_AAD,
        )
        .map_err(Error::Core)?;
        let inner = StateBundleInner::decode(&inner_bytes).map_err(Error::Core)?;

        // 7. Re-derive the side key from the bundle seed; verify it matches.
        let label = "joined".to_owned();
        let new_side_key = SideKey::from_seed(&inner.side_seed, label.clone());
        if new_side_key.public_bytes() != qr.side {
            return Err(Error::Invariant(
                "accept_pairing: bundle seed produces wrong pubkey",
            ));
        }

        // 8. Install the side on this node (its own endpoint).
        let (side_arc, listen) = self
            .add_side(new_side_key, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await?;

        // 9. Replay the bundle's state into the new side.
        if let Some(wire) = &inner.profile_wire {
            let prof = ProfilePayload::from_wire_bytes(wire).map_err(Error::Core)?;
            side_arc.set_profile(prof).await;
        }
        for rec in inner.relationships {
            use std::collections::BTreeSet;
            let caps: BTreeSet<String> = rec.capabilities.into_iter().collect();
            side_arc
                .add_relationship(crate::relationships::SideRelationship {
                    address: rec.address,
                    nickname: rec.nickname,
                    introduced_by: rec.introduced_by,
                    capabilities: caps,
                    notes: rec.notes,
                    pinned: rec.pinned,
                    added_at: rec.added_at,
                    peer_listen_addr: None,
                })
                .await;
        }
        for r in inner.retired_sides {
            side_arc.mark_retired_seen(r).await;
        }
        for dev in inner.co_holders {
            // Skip ourselves (we're not a co-holder of ourselves in the
            // local sense — that's the "other devices" list).
            if dev == device_pubkey {
                continue;
            }
            side_arc.add_co_holder(dev, None).await;
        }
        // Lifecycle: inherit from bundle. If the bundle says Retired, the
        // new device sees this side as retired locally too.
        let lc = match inner.lifecycle.as_str() {
            "Active" => crate::relationships::SideLifecycle::Active,
            "Dormant" => crate::relationships::SideLifecycle::Dormant,
            "Retired" => crate::relationships::SideLifecycle::Retired,
            _ => crate::relationships::SideLifecycle::Created,
        };
        side_arc.set_lifecycle(lc).await;

        // Phase 1.5g: close the address loop. The existing device knew
        // our device_pubkey (from PairingRequest) but not our listen
        // address. Send a CoHolderAdded delta back so future state
        // mutations on the existing device can be pushed to us.
        //
        // The existing device's listen address is `qr.dial_addr`. Record
        // it locally so OUR future mutations push to it too.
        side_arc
            .record_co_holder_addr(qr.side, qr.dial_addr.clone())
            .await;
        side_arc.add_co_holder(qr.side, Some(device_pubkey)).await;

        let our_listen_str = listen.to_string();
        let our_pubkey = device_pubkey;
        let side_addr = side_arc.address;
        // Tokio-spawn so accept_pairing returns promptly; the push is
        // best-effort and uses the standard push helper for the new side.
        self.push_delta_to_co_holders(
            &side_addr,
            vec![DeltaOp::CoHolderAdded {
                device_pubkey: our_pubkey,
                dial_addr: our_listen_str,
            }],
        )
        .await;

        Ok((side_arc, listen))
    }

    /// Snapshot the co-holder device pubkeys for the given hosted side.
    /// Returns an empty Vec if the side has no co-holders or isn't hosted.
    pub async fn list_co_holders(&self, side_addr: &[u8; 32]) -> Vec<[u8; 32]> {
        match self.side_by_address(side_addr).await {
            Some(s) => s
                .list_co_holders()
                .await
                .into_iter()
                .map(|c| c.device_pubkey)
                .collect(),
            None => Vec::new(),
        }
    }

    /// Build (and sign) a `DeviceRevokePayload` removing `device_pubkey`
    /// from `side_addr`'s co-holder set. Also applies locally — the
    /// returned record can be broadcast / announced to other co-holders
    /// via `announce_revocation`. §7.5.
    pub async fn revoke_co_holder(
        &self,
        side_addr: &[u8; 32],
        device_pubkey: [u8; 32],
        reason: Option<String>,
    ) -> Result<DeviceRevokePayload> {
        let side = self
            .side_by_address(side_addr)
            .await
            .ok_or(Error::Invariant("revoke_co_holder: side not hosted"))?;
        let now = sidevers_core::envelope::now_unix_seconds().map_err(Error::Core)?;
        let record = DeviceRevokePayload::sign(side.keypair(), device_pubkey, now, reason)
            .map_err(Error::Core)?;
        side.add_revoked_device(device_pubkey).await;
        side.remove_co_holder(&device_pubkey).await;
        Ok(record)
    }

    /// Send a `DEVICE_REVOKE` envelope on the given Direct session. The
    /// receiver will remove the revoked device from their local
    /// co-holder set.
    pub async fn announce_revocation(
        &self,
        session: &Session,
        side_addr: &[u8; 32],
        record: &DeviceRevokePayload,
    ) -> Result<()> {
        let side = self
            .side_by_address(side_addr)
            .await
            .ok_or(Error::Invariant("announce_revocation: side not hosted"))?;
        let env = Envelope::sign_with(
            MessageType::DEVICE_REVOKE,
            side.keypair(),
            Some(session.peer_side),
            record.to_wire_bytes(),
            sidevers_core::envelope::now_unix_seconds().map_err(Error::Core)?,
            random_nonce()?,
        )
        .map_err(Error::Core)?;
        let (mut send, _recv) = session.open_and_send(&env).await?;
        send.finish().ok();
        let _ = send.stopped().await;
        Ok(())
    }

    /// True iff the given device pubkey is in the revoked list for `side_addr`.
    pub async fn is_device_revoked(&self, side_addr: &[u8; 32], device_pubkey: &[u8; 32]) -> bool {
        match self.side_by_address(side_addr).await {
            Some(s) => s.is_device_revoked(device_pubkey).await,
            None => false,
        }
    }

    // -----------------------------------------------------------------
    // Phase 1.5g: live state delta push between co-holders (§7.5).
    // -----------------------------------------------------------------

    /// Push one or more state ops to every known co-holder of `side_addr`.
    /// Best-effort: dial failures are logged but not surfaced. Each push
    /// runs as a detached `tokio::spawn` so the calling mutator returns
    /// without blocking on the network.
    ///
    /// No-op if the side isn't hosted, has no co-holders, or `ops` is
    /// empty. Logs at `WARN` for sign failures; `DEBUG` for dial /
    /// handshake / send failures.
    #[tracing::instrument(
        name = "delta.push",
        skip(self, ops),
        fields(side = %LogId::new(side_addr), op_count = ops.len())
    )]
    pub async fn push_delta_to_co_holders(&self, side_addr: &[u8; 32], ops: Vec<DeltaOp>) {
        let side = match self.side_by_address(side_addr).await {
            Some(s) => s,
            None => return,
        };
        let addrs = side.list_co_holder_addrs().await;
        if addrs.is_empty() {
            return;
        }
        let applied_at = match sidevers_core::envelope::now_unix_seconds() {
            Ok(t) => t,
            Err(_) => return,
        };
        let delta = match StateDeltaPayload::sign(side.keypair(), ops, applied_at) {
            Ok(d) => d,
            Err(e) => {
                warn!("push_delta: sign failed: {e}");
                return;
            }
        };
        let payload = delta.to_wire_bytes();
        let side_key = side.keypair_arc();
        let endpoint = self.endpoint.clone();
        for (device_pubkey, dial_addr) in addrs {
            let side_key = side_key.clone();
            let endpoint = endpoint.clone();
            let payload = payload.clone();
            tokio::spawn(async move {
                let peer_addr: SocketAddr = match dial_addr.parse() {
                    Ok(a) => a,
                    Err(_) => return,
                };
                let connecting = match endpoint.connect(peer_addr, "sidevers") {
                    Ok(c) => c,
                    Err(e) => {
                        debug!("push_delta dial setup failed for {device_pubkey:02X?}: {e}");
                        return;
                    }
                };
                let conn = match connecting.await {
                    Ok(c) => c,
                    Err(e) => {
                        debug!("push_delta dial failed: {e}");
                        return;
                    }
                };
                let session = match run_initiator(&conn, &side_key, Intent::Direct, None).await {
                    Ok(s) => s,
                    Err(e) => {
                        debug!("push_delta handshake failed: {e}");
                        return;
                    }
                };
                // Wire-protocol timestamps MUST be from a real clock: a
                // timestamp of 0 would be ~50 years stale and the receiver
                // would reject via `check_freshness_and_replay`.
                let ts = match sidevers_core::envelope::now_unix_seconds() {
                    Ok(t) => t,
                    Err(e) => {
                        warn!("push_delta: system clock unavailable: {e}");
                        return;
                    }
                };
                let env = match Envelope::sign_with(
                    MessageType::STATE_DELTA,
                    &side_key,
                    Some(session.peer_side),
                    payload,
                    ts,
                    match random_nonce() {
                        Ok(n) => n,
                        Err(_) => return,
                    },
                ) {
                    Ok(e) => e,
                    Err(e) => {
                        debug!("push_delta sign envelope failed: {e}");
                        return;
                    }
                };
                if let Ok((mut send, _recv)) = session.open_and_send(&env).await {
                    send.finish().ok();
                    let _ = send.stopped().await;
                }
            });
        }
    }

    /// Register a hosted verse with this node. Verse-intent connections
    /// from peers will be served using this state. Phase 1.5.E supports
    /// multiple simultaneously hosted verses — `host_verse` may be
    /// called repeatedly with different verses. Calling it twice with
    /// the same `verse.verse_key` replaces the existing host.
    pub async fn host_verse(&self, verse: VerseHost) {
        let addr = verse.with(|inner| inner.verse_key.public_bytes()).await;
        let mut g = self.services.hosted_verses.lock().await;
        g.insert(addr, verse);
    }

    /// Snapshot the verse addresses this node currently hosts.
    pub async fn hosted_verse_addresses(&self) -> Vec<[u8; 32]> {
        self.services
            .hosted_verses
            .lock()
            .await
            .keys()
            .copied()
            .collect()
    }

    /// Look up a hosted verse by its address.
    pub async fn hosted_verse(&self, verse_addr: &[u8; 32]) -> Option<VerseHost> {
        self.services
            .hosted_verses
            .lock()
            .await
            .get(verse_addr)
            .cloned()
    }

    /// Phase 1.5.A: eagerly rotate the verse content key and push the
    /// new sealed key to every currently-connected member, without
    /// waiting for a leave / remove event. Use this on a schedule
    /// (e.g. weekly) so a long-lived membership can't accumulate
    /// arbitrary plaintext under a single content key.
    ///
    /// Returns `Err` if the named verse isn't hosted on this node.
    pub async fn host_rotate_verse_key(&self, verse_addr: &[u8; 32]) -> Result<()> {
        let host = self
            .hosted_verse(verse_addr)
            .await
            .ok_or(Error::Invariant("rotate: verse not hosted"))?;
        rotate_and_push_verse_key(&host).await
    }

    /// Wait for the next decrypted verse post that arrived on this node's
    /// hosted verse.
    pub async fn next_verse_post(&self) -> Option<VersePostReceived> {
        let mut rx = self.verse_post_rx.lock().await;
        rx.recv().await
    }

    /// Amend the hosted verse's contract to a new version, then push a
    /// `VerseAmend` envelope to every currently-active member session.
    /// Members re-consent via `reconsent_to_amendment` before posting under
    /// the new contract version.
    ///
    /// Per spec §8.7, amendments do not require content-key rotation by
    /// themselves; only membership changes (leave / remove) do. Returns
    /// `Err` if no verse is hosted.
    pub async fn host_amend_verse(&self, new_contract: ContractObject) -> Result<()> {
        // Phase 1.5.E: amend operates on the verse identified by the
        // new contract's `verse` field. Pre-1.5.E this picked "the one
        // hosted verse"; we now look up by address so multi-verse
        // hosts can amend any verse they host.
        let host = {
            let g = self.services.hosted_verses.lock().await;
            match g.get(&new_contract.verse) {
                Some(h) => h.clone(),
                None => return Err(Error::Invariant("no hosted verse for that contract.verse")),
            }
        };
        // Update the host's contract in place.
        host.amend_contract(new_contract.clone()).await;

        // Build one VerseAmend envelope per active member session and push.
        // The envelope is signed by the verse keypair (the contract's signer
        // per §8.7) and addressed to each member.
        use sidevers_core::messages::verse::VerseAmendPayload;
        let payload = VerseAmendPayload {
            contract: new_contract,
        };
        let payload_bytes = payload.encode();
        let pushes: Vec<([u8; 32], quinn::Connection, Envelope)> = host
            .with(|inner| -> Result<_> {
                let now = sidevers_core::envelope::now_unix_seconds()?;
                let mut out = Vec::new();
                for (member_side, conn) in inner.active_sessions.iter() {
                    if !inner.members.contains(member_side) {
                        continue;
                    }
                    let env = Envelope::sign_with(
                        MessageType::VERSE_AMEND,
                        &inner.verse_key,
                        Some(*member_side),
                        payload_bytes.clone(),
                        now,
                        random_nonce()?,
                    )?;
                    out.push((*member_side, conn.clone(), env));
                }
                Ok(out)
            })
            .await?;

        for (member, conn, env) in pushes {
            tokio::spawn(async move {
                if let Ok((mut send, _recv)) = conn.open_bi().await {
                    if send_envelope(&mut send, &env).await.is_ok() {
                        send.finish().ok();
                    }
                }
                let _ = member;
            });
        }
        Ok(())
    }

    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    pub fn side(&self) -> &SideKey {
        &self.services.side
    }

    pub fn store(&self) -> ObjectStore {
        self.services.store.clone()
    }

    pub fn peers(&self) -> PeerTable {
        self.services.peers.clone()
    }

    /// Handle to the per-peer reputation table (spec §6.9 Tier-1
    /// anti-spam). Useful for snapshotting a peer's counters, manually
    /// refusing a peer, or reinstating a refused peer.
    pub fn reputation(&self) -> ReputationTable {
        self.services.reputation.clone()
    }

    /// Handle to the per-source-IP handshake rate limiter (spec §4.6).
    /// Tests inspect this to confirm a throttled peer's bucket; ops can
    /// inspect `tracked()` for cardinality.
    pub fn handshake_limit(&self) -> HandshakeLimiter {
        self.services.handshake_limit.clone()
    }

    /// Snapshot the set of sides currently recorded as publishers of
    /// the content-addressed object `hash` (Phase 1.C3, spec §5.6).
    /// Used by tests to assert retract provenance behavior; ops can
    /// inspect it for diagnostics.
    pub async fn publisher_set(&self, hash: &[u8; 32]) -> std::collections::BTreeSet<[u8; 32]> {
        self.services.provenance.publishers(hash).await
    }

    /// Get the current gossip-fanout policy (Phase 1.A3, spec §6.9.3).
    pub async fn gossip_policy(&self) -> GossipPolicy {
        *self.services.gossip_policy.lock().await
    }

    /// Set the gossip-fanout policy. Takes effect on the next
    /// inbound broadcast that triggers fanout.
    pub async fn set_gossip_policy(&self, policy: GossipPolicy) {
        *self.services.gossip_policy.lock().await = policy;
    }

    /// Handle to the process-wide [`Metrics`] (Phase 1.H3). Clone is
    /// cheap; clones share the same underlying counters. Spawn the
    /// HTTP endpoint via `metrics().serve_on(addr).await`.
    pub fn metrics(&self) -> Metrics {
        self.services.metrics.clone()
    }

    pub fn mailbox(&self) -> Mailbox {
        self.services.mailbox.clone()
    }

    pub fn gossip(&self) -> GossipState {
        self.services.gossip.clone()
    }

    pub fn address(&self) -> Address {
        Address::from_public_key(AddressKind::Side, &self.services.side.public())
    }

    /// Dial a peer at `peer_addr`, run the initiator handshake, return a
    /// `Session` on success. Reuses the node's own endpoint (both server
    /// and client) so the connection's lifetime is tied to the node, not
    /// to a transient client endpoint.
    pub async fn dial(&self, peer_addr: SocketAddr, intent: Intent) -> Result<Session> {
        let connecting = self.endpoint.connect(peer_addr, "sidevers")?;
        let conn = connecting.await?;
        let session = run_initiator(&conn, &self.services.side, intent, None).await?;
        // Cache the underlying transport for future dial_pooled calls.
        self.pool
            .insert(peer_addr, self.services.side.public_bytes(), conn.clone())
            .await;
        let _ = conn;
        // Note the freshly-handshaked peer in our local peer table.
        self.services
            .peers
            .insert(PeerInfo {
                address: session.peer_side,
                intents: vec![intent.as_u8()],
                endpoints: vec![peer_addr.to_string()],
                last_seen: unix_now(),
            })
            .await;
        Ok(session)
    }

    /// Dial anonymously: handshake using a freshly-generated throwaway side
    /// rather than this node's primary side, per spec §4.5.
    ///
    /// Returns `(Session, ephemeral_side)`. The caller keeps the ephemeral
    /// side alive for the lifetime of the session (it's needed to sign
    /// outgoing envelopes on this connection); when the side is dropped,
    /// its secret bytes are zeroized via the inner `SigningKey`'s drop.
    ///
    /// The remote peer only ever sees this throwaway side's public key. It
    /// has no cryptographic link to this node's primary side or to any
    /// previous anonymous dial.
    pub async fn dial_anonymous(
        &self,
        peer_addr: SocketAddr,
        intent: Intent,
    ) -> Result<(Session, SideKey)> {
        // Generate a fresh master, derive an "anon" side, then discard the
        // master. The side's secret is the only thing kept; nothing on the
        // wire reveals it came from our primary identity.
        let ephemeral_master = sidevers_core::keys::MasterKey::generate().map_err(Error::Core)?;
        let ephemeral_side = ephemeral_master
            .derive_side(&"anon".into())
            .map_err(Error::Core)?;
        drop(ephemeral_master);

        let connecting = self.endpoint.connect(peer_addr, "sidevers")?;
        let conn = connecting.await?;
        let session = run_initiator(&conn, &ephemeral_side, intent, None).await?;
        // Deliberately NOT inserted into peer table — the whole point of
        // anonymous dialing is to not record this side anywhere observable.
        Ok((session, ephemeral_side))
    }

    /// Wait for the next DM the responder accepted on this node.
    pub async fn next_direct_message(&self) -> Option<DirectMessageReceived> {
        let mut rx = self.dm_rx.lock().await;
        rx.recv().await
    }

    /// Try to drain a DM without waiting (returns `None` if nothing is queued).
    pub async fn try_next_direct_message(&self) -> Option<DirectMessageReceived> {
        let mut rx = self.dm_rx.lock().await;
        rx.try_recv().ok()
    }

    /// Wait for the next `PROFILE_DELIVER` envelope this node received in
    /// response to a `PROFILE_FETCH` (spec §7.3).
    pub async fn next_profile_delivery(&self) -> Option<ProfileDelivered> {
        let mut rx = self.profile_rx.lock().await;
        rx.recv().await
    }

    /// Wait for the next `LINKAGE_PUBLISH` envelope (spec §2.7). Both
    /// signatures inside have already verified by the time this returns.
    pub async fn next_linkage_proof(&self) -> Option<LinkageProofReceived> {
        let mut rx = self.linkage_rx.lock().await;
        rx.recv().await
    }

    /// Install the profile this node publishes for its hosted side.
    /// Subsequent `PROFILE_FETCH` requests addressed to this side will
    /// reply with the signed profile; the declared capabilities (§7.7)
    /// gate which `Direct`-category messages this node will accept.
    /// Persists to the SideStore.
    pub async fn set_local_profile(&self, profile: ProfilePayload) {
        let wire = profile.to_wire_bytes();
        self.services.side_state.set_profile(profile).await;
        // Phase 1.5g: push to co-holders.
        let side_addr = self.services.side.public_bytes();
        self.push_delta_to_co_holders(
            &side_addr,
            vec![DeltaOp::ProfileUpdated { profile_wire: wire }],
        )
        .await;
    }

    /// Return a clone of the current local profile, if set.
    pub async fn local_profile(&self) -> Option<ProfilePayload> {
        self.services.side_state.profile().await
    }

    /// Build and sign a `SideRetirement` record for this node's hosted side
    /// (spec §7.8). The returned record can be published over a Direct
    /// session via `announce_retirement` or persisted for later use. As a
    /// side effect, flips `lifecycle()` to `Retired` so subsequent local
    /// queries reflect the published state.
    pub async fn publish_retirement(
        &self,
        reason: Option<String>,
    ) -> Result<SideRetirementPayload> {
        let now = sidevers_core::envelope::now_unix_seconds().map_err(Error::Core)?;
        let record =
            SideRetirementPayload::sign(&self.services.side, now, reason).map_err(Error::Core)?;
        self.services.side_state.set_self_retired().await;
        Ok(record)
    }

    /// Phase 3.C / Phase 1.5.f: retire a specific hosted side (not
    /// necessarily the primary). Looks up the side by address, signs
    /// a retirement record with its keypair, and flips its lifecycle
    /// to `Retired`. Returns `Err` if the address isn't hosted here.
    pub async fn retire_side(
        &self,
        side_addr: &[u8; 32],
        reason: Option<String>,
    ) -> Result<SideRetirementPayload> {
        let side = self
            .side_by_address(side_addr)
            .await
            .ok_or(Error::Invariant("retire_side: side not hosted"))?;
        let now = sidevers_core::envelope::now_unix_seconds().map_err(Error::Core)?;
        let keypair = side.keypair_arc();
        let record = SideRetirementPayload::sign(&keypair, now, reason).map_err(Error::Core)?;
        side.set_lifecycle(crate::relationships::SideLifecycle::Retired)
            .await;
        Ok(record)
    }

    /// True iff this node has observed a `SideRetirement` for the given
    /// side public key (spec §7.8).
    pub async fn is_side_retired(&self, side: &[u8; 32]) -> bool {
        self.services.side_state.is_retired_seen(side).await
    }

    // -----------------------------------------------------------------
    // Side relationships (spec §7.4) — local-only contact list.
    // -----------------------------------------------------------------

    /// Insert or replace a relationship for `r.address`. The relationship's
    /// capability set is consulted on every inbound envelope from that
    /// address and takes precedence over the profile. Persists.
    pub async fn add_relationship(&self, r: SideRelationship) {
        let record = RelationshipRecord {
            address: r.address,
            nickname: r.nickname.clone(),
            introduced_by: r.introduced_by,
            capabilities: {
                let mut caps: Vec<String> = r.capabilities.iter().cloned().collect();
                caps.sort();
                caps
            },
            notes: r.notes.clone(),
            pinned: r.pinned,
            added_at: r.added_at,
        };
        self.services.side_state.add_relationship(r).await;
        // Phase 1.5g: push to co-holders.
        let side_addr = self.services.side.public_bytes();
        self.push_delta_to_co_holders(&side_addr, vec![DeltaOp::RelationshipUpserted { record }])
            .await;
    }

    /// Return a snapshot of the relationship for `address`, if any.
    pub async fn get_relationship(&self, address: &[u8; 32]) -> Option<SideRelationship> {
        self.services.side_state.get_relationship(address).await
    }

    /// Remove a relationship. No-op if not present. After removal the
    /// fallback (profile, then default) applies again. Persists.
    pub async fn remove_relationship(&self, address: &[u8; 32]) {
        self.services.side_state.remove_relationship(address).await;
        // Phase 1.5g: push to co-holders.
        let side_addr = self.services.side.public_bytes();
        self.push_delta_to_co_holders(
            &side_addr,
            vec![DeltaOp::RelationshipRemoved { address: *address }],
        )
        .await;
    }

    /// Snapshot all relationships ordered by address.
    pub async fn list_relationships(&self) -> Vec<SideRelationship> {
        self.services.side_state.list_relationships().await
    }

    /// Mutate a relationship in place under the table lock. Returns the
    /// pre-edit relationship as a snapshot if present; `None` if not
    /// found (and the closure is never invoked).
    pub async fn update_relationship<F>(&self, address: &[u8; 32], f: F) -> Option<SideRelationship>
    where
        F: FnOnce(&mut SideRelationship),
    {
        self.services
            .side_state
            .update_relationship(address, f)
            .await
    }

    // -----------------------------------------------------------------
    // Side lifecycle (spec §7.8) — Created / Active / Dormant / Retired.
    // -----------------------------------------------------------------

    /// Current lifecycle state. Updated by `touch_local_send` (Created →
    /// Active) and by `publish_retirement` (→ Retired). Callers who want
    /// the activity-window-aware Dormant transition should call
    /// `refresh_lifecycle` first.
    pub async fn lifecycle(&self) -> SideLifecycle {
        self.services.side_state.lifecycle().await
    }

    /// Manually pin the lifecycle to `state`. Use sparingly; the usual
    /// transitions are automatic. Notably the conformance harness uses
    /// this to test Dormant without time-traveling the clock.
    pub async fn set_lifecycle(&self, state: SideLifecycle) {
        self.services.side_state.set_lifecycle(state).await
    }

    /// Re-derive the lifecycle from `last_local_send_at` + retirement
    /// status. If the current state is Retired, leave it (retirement
    /// is sticky). Otherwise apply `SideLifecycle::derive(...)`.
    pub async fn refresh_lifecycle(&self) {
        self.services.side_state.refresh_lifecycle().await
    }

    // -----------------------------------------------------------------
    // Outbound wrappers that update lifecycle (Created → Active on first
    // send). The bare free-function helpers (`send_dm`, `announce_retirement`,
    // etc.) are still available for callers that don't care about
    // lifecycle, but the Node methods are the recommended path.
    // -----------------------------------------------------------------

    /// Send a single DirectMessage using this node's hosted side, then
    /// stamp `last_local_send_at` and advance lifecycle (Created → Active).
    pub async fn send_dm(&self, session: &Session, plaintext: &[u8]) -> Result<()> {
        send_dm(session, &self.services.side, plaintext).await?;
        touch_local_send(&self.services).await;
        Ok(())
    }

    /// Announce a previously-built `SideRetirementPayload` to the peer
    /// on this Direct session, stamping the send timestamp. The lifecycle
    /// transition to `Retired` already happened inside
    /// `Node::publish_retirement`.
    pub async fn announce_retirement(
        &self,
        session: &Session,
        record: &SideRetirementPayload,
    ) -> Result<()> {
        announce_retirement(session, &self.services.side, record).await?;
        touch_local_send(&self.services).await;
        Ok(())
    }

    /// Wait for the next public broadcast that this node received (and
    /// considered novel via the gossip dedup cache).
    pub async fn next_public_broadcast(&self) -> Option<Envelope> {
        let mut rx = self.gossip_rx.lock().await;
        rx.recv().await
    }

    pub async fn shutdown(self) {
        self.accept_handle.abort();
        self.endpoint.close(0u32.into(), b"shutdown");
        let _ = self.endpoint.wait_idle().await;
        // Shut down each secondary side's endpoint + accept loop.
        let extras = self.extras.lock().await;
        for s in extras.iter() {
            s.accept_handle.abort();
            s.endpoint.close(0u32.into(), b"shutdown");
            let _ = s.endpoint.wait_idle().await;
        }
    }
}

#[tracing::instrument(
    name = "accept.loop",
    skip(endpoint, services),
    fields(side = %LogId::new(&services.side.public_bytes())),
)]
async fn accept_loop(endpoint: quinn::Endpoint, services: Services) {
    while let Some(incoming) = endpoint.accept().await {
        let services = services.clone();
        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => {
                    if let Err(e) = handle_connection(conn, services).await {
                        debug!("connection ended: {e}");
                    }
                }
                Err(e) => {
                    debug!("connection accept failed: {e}");
                }
            }
        });
    }
}

#[tracing::instrument(
    name = "handle.connection",
    skip(conn, services),
    fields(remote = %conn.remote_address()),
    err
)]
async fn handle_connection(conn: quinn::Connection, services: Services) -> Result<()> {
    // Phase 1.D / §4.6: per-source-IP handshake rate limit. Refusing
    // here saves the responder X25519 + signature work for sources
    // pumping new connections; the QUIC connection is dropped without
    // even accepting the handshake bi-stream.
    let remote_ip = conn.remote_address().ip();
    if !services.handshake_limit.try_acquire(remote_ip).await {
        debug!(ip = %remote_ip, "handshake throttled: too many recent connections from this source");
        services.metrics.incr_handshake_throttled();
        conn.close(0u32.into(), b"handshake rate limit");
        return Ok(());
    }
    let (mut hs_send, mut hs_recv) = conn.accept_bi().await?;
    let session = run_responder(&mut hs_send, &mut hs_recv, &services.side, &conn).await?;

    // Remember the peer in our peer table on handshake completion.
    let remote_endpoint = conn.remote_address().to_string();
    services
        .peers
        .insert(PeerInfo {
            address: session.peer_side,
            intents: vec![session.intent.as_u8()],
            endpoints: vec![remote_endpoint],
            last_seen: unix_now(),
        })
        .await;

    match session.intent {
        Intent::Direct => serve_direct(session, services).await,
        Intent::Storage => serve_storage(session, services).await,
        Intent::Gossip => serve_gossip(session, services).await,
        Intent::Verse => serve_verse(session, services).await,
        Intent::PublicLayer => {
            debug!("intent {:?} not implemented; closing", session.intent);
            Ok(())
        }
    }
}

#[tracing::instrument(
    name = "serve.direct",
    skip(session, services),
    fields(peer = %LogId::new(&session.peer_side)),
    err
)]
async fn serve_direct(session: Session, services: Services) -> Result<()> {
    loop {
        let (mut send, _recv, env) = match session.accept_one().await {
            Ok(triple) => triple,
            Err(Error::Connection(quinn::ConnectionError::ApplicationClosed(_)))
            | Err(Error::Connection(quinn::ConnectionError::ConnectionClosed(_)))
            | Err(Error::Connection(quinn::ConnectionError::LocallyClosed))
            | Err(Error::Connection(quinn::ConnectionError::TimedOut)) => return Ok(()),
            Err(e) => return Err(e),
        };
        if !check_reputation_gate(&env, &services).await {
            debug!("envelope dropped: peer rate-limited or refused");
            continue;
        }
        if !check_freshness_and_replay_metered(&env, &services.replay, Some(&services.metrics))
            .await
        {
            warn!("dm rejected: stale or replayed");
            continue;
        }
        // §7.8: a signature from a side this node has marked retired is
        // not rejected, but is surfaced as anomalous.
        check_retirement(&env, &services).await;
        match env.message_type {
            MessageType::DIRECT_MESSAGE => {
                // §7.4 + §7.7: relationship-specific capability (if any)
                // wins, then profile capabilities, then a permissive
                // default so legacy nodes / the existing test suite work
                // unchanged.
                if !capability_allows(
                    &services,
                    &env.from,
                    profile_msg::capability::DIRECT_MESSAGE,
                )
                .await
                {
                    debug!("DM rejected: recipient policy denies direct-message from this sender");
                    continue;
                }
                let plaintext = match core_payload::open(
                    &env.payload,
                    &services.side,
                    &env.from,
                    &env.nonce,
                    b"",
                ) {
                    Ok(p) => p,
                    Err(_) => {
                        warn!("dm decrypt failed");
                        continue;
                    }
                };
                let _ = services
                    .dm_tx
                    .send(DirectMessageReceived {
                        envelope: env,
                        plaintext,
                    })
                    .await;
                services.metrics.incr_dm_received();
            }
            MessageType::PROFILE_FETCH => {
                // Payload: 32-byte side address being queried. Answer only
                // if it matches our hosted side AND we have a profile set.
                if env.payload.len() != 32 {
                    debug!("PROFILE_FETCH: payload not 32 bytes");
                    continue;
                }
                let mut queried = [0u8; 32];
                queried.copy_from_slice(&env.payload);
                if queried != services.side.public_bytes() {
                    debug!("PROFILE_FETCH: not for our hosted side; ignoring");
                    continue;
                }
                let profile = match services.side_state.profile().await {
                    Some(p) => p,
                    None => {
                        debug!("PROFILE_FETCH: no local profile set; dropping");
                        continue;
                    }
                };
                let resp = sign_response(
                    &services.side,
                    &env.from,
                    MessageType::PROFILE_DELIVER,
                    profile.to_wire_bytes(),
                )?;
                send_envelope(&mut send, &resp).await?;
                send.finish().ok();
            }
            MessageType::PROFILE_DELIVER => {
                let profile = match ProfilePayload::from_wire_bytes(&env.payload) {
                    Ok(p) => p,
                    Err(e) => {
                        warn!("PROFILE_DELIVER decode/verify failed: {e}");
                        continue;
                    }
                };
                // Defense in depth: envelope was signed by env.from; the
                // profile inside was signed by profile.side. They must
                // match — otherwise a man-in-the-middle could ship a
                // valid profile for a third party.
                if profile.side != env.from {
                    debug!("PROFILE_DELIVER: profile.side != env.from; dropping");
                    continue;
                }
                let _ = services
                    .profile_tx
                    .send(ProfileDelivered {
                        envelope: env,
                        profile,
                    })
                    .await;
            }
            MessageType::SIDE_RETIREMENT => {
                let record = match SideRetirementPayload::from_wire_bytes(&env.payload) {
                    Ok(r) => r,
                    Err(e) => {
                        warn!("SIDE_RETIREMENT decode/verify failed: {e}");
                        continue;
                    }
                };
                if record.side != env.from {
                    debug!("SIDE_RETIREMENT: record.side != env.from; dropping");
                    continue;
                }
                services.side_state.mark_retired_seen(record.side).await;
            }
            MessageType::LINKAGE_PUBLISH => {
                // §2.7: the envelope payload is the canonical CBOR of a
                // LinkageProof. `from_wire_bytes` already validates both
                // signatures and rejects non-canonical encodings. The
                // sender (envelope.from) must be one of the two linked
                // sides — otherwise a third party could relay a proof
                // they didn't sign, which is fine cryptographically but
                // confusing semantically.
                let proof = match LinkageProof::from_wire_bytes(&env.payload) {
                    Ok(p) => p,
                    Err(e) => {
                        warn!("LINKAGE_PUBLISH decode/verify failed: {e}");
                        continue;
                    }
                };
                if env.from != proof.side_a && env.from != proof.side_b {
                    debug!(
                        "LINKAGE_PUBLISH: sender ({}) is neither linked side; dropping",
                        LogId::new(&env.from)
                    );
                    continue;
                }
                let _ = services
                    .linkage_tx
                    .send(LinkageProofReceived {
                        envelope: env,
                        proof,
                    })
                    .await;
                services.metrics.incr_linkage_proof_received();
            }
            MessageType::DEVICE_PAIRING_REQUEST => {
                // §7.5: the existing device receives a pairing request from
                // the new device. Capability gate is BYPASSED here because
                // the new device has no prior relationship; the QR-shared
                // nonce is the consent token.
                let req = match PairingRequestPayload::from_wire_bytes(&env.payload) {
                    Ok(r) => r,
                    Err(e) => {
                        warn!("DEVICE_PAIRING_REQUEST decode/verify failed: {e}");
                        continue;
                    }
                };
                if req.side != services.side.public_bytes() {
                    debug!("DEVICE_PAIRING_REQUEST: side mismatch for this endpoint");
                    continue;
                }
                // Confirm the nonce was minted by us and is still valid.
                if services
                    .side_state
                    .take_pending_pairing(&req.nonce)
                    .await
                    .is_none()
                {
                    debug!("DEVICE_PAIRING_REQUEST: unknown / expired nonce");
                    continue;
                }
                // Build the state bundle from this side's current state.
                let inner = match build_state_bundle_inner(&services).await {
                    Ok(b) => b,
                    Err(e) => {
                        warn!("DEVICE_PAIRING_REQUEST: failed to build bundle: {e}");
                        continue;
                    }
                };
                let inner_bytes = inner.encode();
                let key_nonce = match random_nonce() {
                    Ok(n) => n,
                    Err(_) => continue,
                };
                let sealed = match core_payload::seal(
                    &inner_bytes,
                    &services.side,
                    &req.device_x25519_pubkey,
                    &key_nonce,
                    STATE_BUNDLE_AAD,
                ) {
                    Ok(c) => c,
                    Err(e) => {
                        warn!("DEVICE_PAIRING_REQUEST: seal failed: {e}");
                        continue;
                    }
                };
                let bundle = match StateBundlePayload::sign(
                    &services.side,
                    req.device_pubkey,
                    req.nonce,
                    key_nonce,
                    sealed,
                ) {
                    Ok(b) => b,
                    Err(e) => {
                        warn!("DEVICE_PAIRING_REQUEST: sign bundle: {e}");
                        continue;
                    }
                };
                let resp_env = sign_response(
                    &services.side,
                    &env.from,
                    MessageType::DEVICE_STATE_BUNDLE,
                    bundle.to_wire_bytes(),
                )?;
                send_envelope(&mut send, &resp_env).await?;
                send.finish().ok();
                // Record the new device as a co-holder.
                services
                    .side_state
                    .add_co_holder(req.device_pubkey, Some(services.side.public_bytes()))
                    .await;
            }
            MessageType::DEVICE_REVOKE => {
                let record = match DeviceRevokePayload::from_wire_bytes(&env.payload) {
                    Ok(r) => r,
                    Err(e) => {
                        warn!("DEVICE_REVOKE decode/verify failed: {e}");
                        continue;
                    }
                };
                if record.side != services.side.public_bytes() {
                    debug!("DEVICE_REVOKE: side mismatch for this endpoint");
                    continue;
                }
                // The signature was already verified inside from_wire_bytes
                // against the side's pubkey (any co-holder can produce one).
                services
                    .side_state
                    .add_revoked_device(record.device_pubkey)
                    .await;
                services
                    .side_state
                    .remove_co_holder(&record.device_pubkey)
                    .await;
            }
            MessageType::DEVICE_STATE_BUNDLE => {
                // Unsolicited STATE_BUNDLE arriving on the accept loop is
                // not handled here — the new device's `accept_pairing`
                // reads the bundle directly off its own send stream.
                debug!("DEVICE_STATE_BUNDLE: unsolicited; ignoring");
            }
            MessageType::STATE_DELTA => {
                // Phase 1.5g: state delta pushed by a co-holder. The
                // outer envelope's signature is verified by the framing
                // layer; the inner StateDeltaPayload also carries a
                // signature against the side's pubkey (any co-holder can
                // produce one).
                let delta = match StateDeltaPayload::from_wire_bytes(&env.payload) {
                    Ok(d) => d,
                    Err(e) => {
                        warn!("STATE_DELTA decode/verify failed: {e}");
                        continue;
                    }
                };
                if delta.side != services.side.public_bytes() {
                    debug!("STATE_DELTA: side mismatch for this endpoint");
                    continue;
                }
                for op in &delta.ops {
                    services.side_state.apply_delta(op, delta.applied_at).await;
                }
            }
            other => {
                debug!("direct server: unexpected type 0x{:02X}", other.0);
            }
        }
    }
}

/// Build the inner state bundle from a side's current state. Used by the
/// existing device to assemble a state snapshot for a new co-holder.
async fn build_state_bundle_inner(services: &Services) -> Result<StateBundleInner> {
    let side = &services.side;
    let side_state = &services.side_state;

    let profile_wire = side_state.profile().await.map(|p| p.to_wire_bytes());

    let rels = side_state.list_relationships().await;
    let mut relationships: Vec<RelationshipRecord> = rels
        .into_iter()
        .map(|r| {
            let mut caps: Vec<String> = r.capabilities.iter().cloned().collect();
            caps.sort();
            RelationshipRecord {
                address: r.address,
                nickname: r.nickname,
                introduced_by: r.introduced_by,
                capabilities: caps,
                notes: r.notes,
                pinned: r.pinned,
                added_at: r.added_at,
            }
        })
        .collect();
    relationships.sort_by_key(|a| a.address);

    let mut retired_sides: Vec<[u8; 32]> = side_state
        .store()
        .list_retired_seen(&side.public_bytes())
        .await?;
    retired_sides.sort();

    let mut co_holders: Vec<[u8; 32]> = side_state
        .list_co_holders()
        .await
        .into_iter()
        .map(|c| c.device_pubkey)
        .collect();
    co_holders.sort();

    let lifecycle = match side_state.lifecycle().await {
        crate::relationships::SideLifecycle::Created => "Created",
        crate::relationships::SideLifecycle::Active => "Active",
        crate::relationships::SideLifecycle::Dormant => "Dormant",
        crate::relationships::SideLifecycle::Retired => "Retired",
    }
    .to_owned();

    // Informational only — the new device uses this to track when state
    // was bundled, but doesn't reject based on the value.
    let bundled_at = sidevers_core::envelope::now_unix_seconds().unwrap_or_else(|e| {
        warn!("build_state_bundle_inner: system clock unavailable: {e}");
        0
    });
    Ok(StateBundleInner {
        side_seed: side.to_seed(),
        profile_wire,
        relationships,
        retired_sides,
        lifecycle,
        co_holders,
        bundled_at,
    })
}

#[tracing::instrument(
    name = "serve.storage",
    skip(session, services),
    fields(peer = %LogId::new(&session.peer_side)),
    err
)]
async fn serve_storage(session: Session, services: Services) -> Result<()> {
    loop {
        let (mut send, mut recv, env) = match session.accept_one().await {
            Ok(triple) => triple,
            Err(Error::Connection(quinn::ConnectionError::ApplicationClosed(_)))
            | Err(Error::Connection(quinn::ConnectionError::ConnectionClosed(_)))
            | Err(Error::Connection(quinn::ConnectionError::LocallyClosed))
            | Err(Error::Connection(quinn::ConnectionError::TimedOut)) => return Ok(()),
            Err(e) => return Err(e),
        };
        if !check_reputation_gate(&env, &services).await {
            debug!("envelope dropped: peer rate-limited or refused");
            continue;
        }
        if !check_freshness_and_replay_metered(&env, &services.replay, Some(&services.metrics))
            .await
        {
            warn!("storage envelope rejected: stale or replayed");
            continue;
        }
        match env.message_type {
            MessageType::STORAGE_GET => {
                let req = match StorageGetPayload::decode(&env.payload) {
                    Ok(r) => r,
                    Err(e) => {
                        warn!("storage get decode failed: {e}");
                        continue;
                    }
                };
                let resp_env =
                    build_storage_response(&services.side, &env.from, &services.store, &req)
                        .await?;
                send_envelope(&mut send, &resp_env).await?;
                send.finish().ok();
            }
            MessageType::STORAGE_OFFER => {
                // §5.5: offer/want negotiation. We accept the offer iff we
                // don't already have the bytes; the offerer follows up with
                // a `StorageHave` on the same stream.
                use crate::storage_protocol::StorageOfferPayload;
                let offer = match StorageOfferPayload::decode(&env.payload) {
                    Ok(o) => o,
                    Err(e) => {
                        warn!("storage offer decode failed: {e}");
                        continue;
                    }
                };
                let already_have = services
                    .store
                    .has(&offer.reference.hash)
                    .await
                    .unwrap_or(false);
                let want_payload = StorageWantPayload {
                    hash: offer.reference.hash,
                    want: !already_have,
                };
                let want_env = sign_response(
                    &services.side,
                    &env.from,
                    MessageType::STORAGE_WANT,
                    want_payload.encode(),
                )?;
                send_envelope(&mut send, &want_env).await?;
                if already_have {
                    send.finish().ok();
                    continue;
                }
                // Expect a follow-up `StorageHave` on the same stream.
                let have_env = match crate::framing::recv_envelope(&mut recv).await {
                    Ok(e) => e,
                    Err(_) => {
                        send.finish().ok();
                        continue;
                    }
                };
                if have_env.message_type != MessageType::STORAGE_HAVE {
                    debug!("storage offer: expected HAVE follow-up");
                    send.finish().ok();
                    continue;
                }
                let have = match StorageHavePayload::decode(&have_env.payload) {
                    Ok(h) => h,
                    Err(e) => {
                        warn!("storage have decode failed: {e}");
                        send.finish().ok();
                        continue;
                    }
                };
                if have.hash != offer.reference.hash {
                    warn!("storage offer: HAVE hash mismatch");
                    send.finish().ok();
                    continue;
                }
                // Hash-verify and ingest. ObjectStore::put recomputes BLAKE3
                // and rejects on mismatch as a side effect of its content-
                // addressed insertion semantics.
                match services.store.put(have.bytes).await {
                    Ok(addr) if addr == offer.reference.hash => {
                        debug!("storage: ingested 0x{:02x}…", addr[0]);
                        // Phase 1.C3: note the offering peer as a publisher
                        // of this object. A subsequent retract from this
                        // same peer can narrow / drop the object; retracts
                        // from anyone else are now refused.
                        services.provenance.note_publisher(&addr, &env.from).await;
                    }
                    Ok(_) => warn!("storage offer: ingested hash mismatch"),
                    Err(e) => warn!("storage offer: ingest failed: {e}"),
                }
                send.finish().ok();
            }
            MessageType::STORAGE_RETRACT => {
                // §5.6 + Phase 1.C3: retract is a signed statement from
                // the publisher asking honest nodes to stop serving an
                // object. We track who has offered each hash to us
                // (publisher provenance) so an unrelated peer cannot
                // cause us to drop an object they never owned. Only
                // when *every* recorded publisher has retracted do we
                // actually unpin.
                let retract = match StorageRetractPayload::decode(&env.payload) {
                    Ok(r) => r,
                    Err(e) => {
                        warn!("storage retract decode failed: {e}");
                        continue;
                    }
                };
                if !services
                    .provenance
                    .has_publisher(&retract.hash, &env.from)
                    .await
                {
                    debug!(
                        "storage retract: sender ({}) never published 0x{:02x}…; ignoring",
                        LogId::new(&env.from),
                        retract.hash[0]
                    );
                    services.metrics.incr_storage_retract_ignored();
                    continue;
                }
                let others_remain = services
                    .provenance
                    .drop_publisher(&retract.hash, &env.from)
                    .await;
                if others_remain {
                    debug!(
                        "storage retract: {} dropped; other publishers still back 0x{:02x}…",
                        LogId::new(&env.from),
                        retract.hash[0]
                    );
                    continue;
                }
                if services.store.has(&retract.hash).await.unwrap_or(false) {
                    let _ = services.store.unpin(&retract.hash).await;
                    debug!(
                        "storage retract: last publisher retracted; unpinned 0x{:02x}…",
                        retract.hash[0]
                    );
                }
            }
            other => {
                debug!("storage server: unexpected type 0x{:02X}", other.0);
            }
        }
    }
}

/// Serve a Gossip-intent connection: peer-exchange, rendezvous, forward,
/// and broadcast public messages. Deliver any pending forwards for this
/// peer up-front before entering the accept loop.
#[tracing::instrument(
    name = "serve.gossip",
    skip(session, services),
    fields(peer = %LogId::new(&session.peer_side)),
    err
)]
async fn serve_gossip(session: Session, services: Services) -> Result<()> {
    // Track this connection for fan-out of novel broadcasts.
    {
        let mut active = services.active_gossip.lock().await;
        active.insert(session.peer_side, session.connection.clone());
    }
    let _guard = scopeguard_gossip(services.active_gossip.clone(), session.peer_side);

    // 1. Deliver any pending forwards for this peer. Phase 1.B2:
    //    failures are not silently dropped — any held message we
    //    can't push back over the open session is re-stored so a
    //    later reconnect can retry it (subject to the original TTL,
    //    not refreshed).
    let held = services.mailbox.drain(&session.peer_side).await;
    let now = unix_now();
    for msg in held {
        // Skip messages that have already expired in flight (unlikely
        // but cheap to check).
        if msg.expires_at <= now {
            continue;
        }
        let payload = ForwardDeliverPayload {
            envelope: msg.envelope.clone(),
            stored_at: msg.stored_at,
        };
        let env = match sign_response(
            &services.side,
            &session.peer_side,
            MessageType::FORWARD_DELIVER,
            payload.encode(),
        ) {
            Ok(e) => e,
            Err(e) => {
                warn!("forward-deliver: sign failed: {e}; re-storing");
                let remaining = msg.expires_at.saturating_sub(now);
                services
                    .mailbox
                    .store(session.peer_side, msg.envelope, remaining)
                    .await;
                continue;
            }
        };
        match session.open_and_send(&env).await {
            Ok((mut send, _recv)) => {
                send.finish().ok();
            }
            Err(e) => {
                debug!("forward-deliver: transient send failure: {e}; re-storing for retry");
                let remaining = msg.expires_at.saturating_sub(now);
                services
                    .mailbox
                    .store(session.peer_side, msg.envelope, remaining)
                    .await;
                services.metrics.incr_forward_retry();
            }
        }
    }

    // 2. Accept-loop: handle the peer's gossip-category traffic.
    loop {
        let (mut send, _recv, env) = match session.accept_one().await {
            Ok(triple) => triple,
            Err(Error::Connection(quinn::ConnectionError::ApplicationClosed(_)))
            | Err(Error::Connection(quinn::ConnectionError::ConnectionClosed(_)))
            | Err(Error::Connection(quinn::ConnectionError::LocallyClosed))
            | Err(Error::Connection(quinn::ConnectionError::TimedOut)) => return Ok(()),
            Err(e) => return Err(e),
        };
        if !check_reputation_gate(&env, &services).await {
            debug!("envelope dropped: peer rate-limited or refused");
            continue;
        }
        if !check_freshness_and_replay_metered(&env, &services.replay, Some(&services.metrics))
            .await
        {
            warn!("gossip envelope rejected: stale or replayed");
            continue;
        }
        match env.message_type {
            MessageType::PEER_ASK => {
                let req = match PeerAskPayload::decode(&env.payload) {
                    Ok(r) => r,
                    Err(e) => {
                        warn!("peer-ask decode failed: {e}");
                        continue;
                    }
                };
                let peers = services
                    .peers
                    .sample(req.limit.min(256) as usize, req.intent_filter)
                    .await;
                let payload = PeerTellPayload { peers };
                let resp = sign_response(
                    &services.side,
                    &env.from,
                    MessageType::PEER_TELL,
                    payload.encode(),
                )?;
                send_envelope(&mut send, &resp).await?;
                send.finish().ok();
            }
            MessageType::RENDEZVOUS => {
                let req = match RendezvousPayload::decode(&env.payload) {
                    Ok(r) => r,
                    Err(e) => {
                        warn!("rendezvous decode failed: {e}");
                        continue;
                    }
                };
                let endpoints = services
                    .peers
                    .get(&req.target)
                    .await
                    .map(|p| p.endpoints)
                    .unwrap_or_default();
                let payload = RendezvousAckPayload {
                    target: req.target,
                    endpoints,
                };
                let resp = sign_response(
                    &services.side,
                    &env.from,
                    MessageType::RENDEZVOUS_ACK,
                    payload.encode(),
                )?;
                send_envelope(&mut send, &resp).await?;
                send.finish().ok();
            }
            MessageType::FORWARD_STORE => {
                let req = match ForwardStorePayload::decode(&env.payload) {
                    Ok(r) => r,
                    Err(e) => {
                        warn!("forward-store decode failed: {e}");
                        continue;
                    }
                };
                services
                    .mailbox
                    .store(req.recipient, req.envelope, req.ttl_secs)
                    .await;
            }
            other if other.category() == sidevers_core::envelope::MessageCategory::Public => {
                // Broadcast public message (gossip): dedup, then surface
                // locally and fan out to other active gossip connections.
                if services.gossip.observe(&env).await {
                    fanout_broadcast(&services, &env, &session.peer_side).await;
                    let _ = services.gossip_tx.send(env).await;
                    services.metrics.incr_broadcast_received();
                }
            }
            other => {
                debug!("gossip server: ignoring 0x{:02X}", other.0);
            }
        }
    }
}

/// Serve a Verse-intent connection: dispatch ContractFetch, JoinRequest,
/// and VersePost against the node's hosted verse (if any). Phase 1.5a only
/// handles a single hosted verse per node.
#[tracing::instrument(
    name = "serve.verse",
    skip(session, services),
    fields(peer = %LogId::new(&session.peer_side)),
    err
)]
async fn serve_verse(session: Session, services: Services) -> Result<()> {
    // Phase 1.5.E: snapshot every hosted verse + build a
    // contract-hash → verse-addr index for messages that only carry
    // contract_hash. No verses → close immediately.
    let (hosts, contract_hash_index) = {
        let g = services.hosted_verses.lock().await;
        if g.is_empty() {
            debug!("verse intent received but no verses hosted; closing");
            return Ok(());
        }
        let mut hosts = std::collections::HashMap::new();
        let mut idx = std::collections::HashMap::new();
        for (addr, h) in g.iter() {
            hosts.insert(*addr, h.clone());
        }
        drop(g);
        for (addr, h) in hosts.iter() {
            let hash = h.contract().await.hash();
            idx.insert(hash, *addr);
        }
        (hosts, idx)
    };

    // For backward compatibility: pick a "default" verse (used when a
    // payload carries no routing field). With exactly one host this is
    // unambiguous; with several we pick deterministically by the
    // lowest address.
    let mut default_addr_opt: Option<[u8; 32]> = None;
    for addr in hosts.keys() {
        if default_addr_opt.is_none_or(|cur| addr < &cur) {
            default_addr_opt = Some(*addr);
        }
    }
    // `hosts` was just checked non-empty above; default_addr_opt is Some
    // and the address is a key in `hosts`. If a future refactor breaks
    // either invariant we'd rather drop the session than panic.
    let host = match default_addr_opt.and_then(|addr| hosts.get(&addr).cloned()) {
        Some(h) => h,
        None => {
            debug!("serve_verse: hosts table inconsistent; closing");
            return Ok(());
        }
    };

    // Register this peer's Verse-intent connection for post fanout + key
    // rotation push, on every hosted verse so any of them can fan out
    // to this peer if they admit them. RAII guards remove on exit.
    let peer_side = session.peer_side;
    for h in hosts.values() {
        h.with_mut(|inner| {
            inner
                .active_sessions
                .insert(peer_side, session.connection.clone());
        })
        .await;
    }
    let _guards: Vec<VerseSessionGuard> = hosts
        .values()
        .cloned()
        .map(|h| VerseSessionGuard { host: h, peer_side })
        .collect();

    // Audit P1.D — on reconnect, redeliver any key-rotation envelopes
    // stashed from a prior failed push. Each host is independent; we
    // try once and re-stash on failure so the next reconnect tries
    // again. The stash is keyed by member side, so a later rotation
    // that supersedes this one will overwrite the entry.
    for h in hosts.values() {
        if let Some(env) = h.take_pending_key_push(&peer_side).await {
            match session.connection.open_bi().await {
                Ok((mut send, _recv)) => match send_envelope(&mut send, &env).await {
                    Ok(()) => {
                        send.finish().ok();
                        debug!(
                            member = %LogId::new(&peer_side),
                            "verse key rotation: redelivered stashed envelope on reconnect"
                        );
                    }
                    Err(_) => {
                        h.stash_pending_key_push(peer_side, env).await;
                    }
                },
                Err(_) => {
                    h.stash_pending_key_push(peer_side, env).await;
                }
            }
        }
    }

    loop {
        let (mut send, _recv, env) = match session.accept_one().await {
            Ok(triple) => triple,
            Err(Error::Connection(quinn::ConnectionError::ApplicationClosed(_)))
            | Err(Error::Connection(quinn::ConnectionError::ConnectionClosed(_)))
            | Err(Error::Connection(quinn::ConnectionError::LocallyClosed))
            | Err(Error::Connection(quinn::ConnectionError::TimedOut)) => return Ok(()),
            Err(e) => return Err(e),
        };
        if !check_reputation_gate(&env, &services).await {
            debug!("envelope dropped: peer rate-limited or refused");
            continue;
        }
        if !check_freshness_and_replay_metered(&env, &services.replay, Some(&services.metrics))
            .await
        {
            warn!("verse envelope rejected: stale or replayed");
            continue;
        }

        match env.message_type {
            MessageType::CONTRACT_FETCH => {
                let contract = host.contract().await;
                let payload = ContractDeliverPayload { contract };
                let resp = sign_response(
                    &services.side,
                    &env.from,
                    MessageType::CONTRACT_DELIVER,
                    payload.encode(),
                )?;
                send_envelope(&mut send, &resp).await?;
                send.finish().ok();
            }
            MessageType::JOIN_REQUEST => {
                let req = match JoinRequestPayload::decode(&env.payload) {
                    Ok(r) => r,
                    Err(e) => {
                        warn!("JoinRequest decode failed: {e}");
                        continue;
                    }
                };
                // Phase 1.5.E: route by contract_hash to the host whose
                // current contract matches. Pre-1.5.E this used the
                // default-host's contract and would silently decline
                // legitimate joins to a different hosted verse.
                let host = match contract_hash_index
                    .get(&req.contract_hash)
                    .and_then(|addr| hosts.get(addr))
                {
                    Some(h) => h.clone(),
                    None => host.clone(),
                };
                // Verify the contract hash matches our current contract.
                let contract = host.contract().await;
                let expected_hash = contract.hash();
                if req.contract_hash != expected_hash {
                    let decline = JoinDeclinePayload {
                        contract_hash: expected_hash,
                        reason: "contract-version-mismatch".into(),
                    };
                    let resp = sign_response(
                        &services.side,
                        &env.from,
                        MessageType::JOIN_DECLINE,
                        decline.encode(),
                    )?;
                    send_envelope(&mut send, &resp).await?;
                    send.finish().ok();
                    continue;
                }
                // §8.4 field-kind enforcement — "the verse refuses to
                // accept fields whose declared kind is forbidden ...
                // enforced mechanically at the protocol layer."
                // - Required: every kind in contract.required MUST appear
                //   in req.fields. Otherwise reason = "missing-required".
                // - Forbidden: no kind in req.fields may match an entry
                //   in contract.forbidden. Otherwise reason = "forbidden-field".
                if let Some(missing) = contract
                    .required
                    .iter()
                    .find(|spec| !req.fields.contains_key(&spec.kind))
                {
                    debug!(
                        "JoinRequest declined: missing required kind {:?}",
                        missing.kind
                    );
                    let decline = JoinDeclinePayload {
                        contract_hash: expected_hash,
                        reason: "missing-required".into(),
                    };
                    let resp = sign_response(
                        &services.side,
                        &env.from,
                        MessageType::JOIN_DECLINE,
                        decline.encode(),
                    )?;
                    send_envelope(&mut send, &resp).await?;
                    send.finish().ok();
                    continue;
                }
                if let Some(bad_kind) = req.fields.keys().find(|k| contract.is_forbidden(k)) {
                    debug!("JoinRequest declined: forbidden kind {:?}", bad_kind);
                    let decline = JoinDeclinePayload {
                        contract_hash: expected_hash,
                        reason: "forbidden-field".into(),
                    };
                    let resp = sign_response(
                        &services.side,
                        &env.from,
                        MessageType::JOIN_DECLINE,
                        decline.encode(),
                    )?;
                    send_envelope(&mut send, &resp).await?;
                    send.finish().ok();
                    continue;
                }
                // Build a fresh membership token + seal the content key to
                // the joining side, all under the verse's keypair.
                let (verse_pk, token_bytes, key_nonce, sealed) = host
                    .with(|inner| -> Result<_> {
                        let token = MembershipToken::sign(
                            &inner.verse_key,
                            expected_hash,
                            req.side,
                            sidevers_core::envelope::now_unix_seconds()?,
                        )?;
                        let key_nonce = random_nonce()?;
                        let sealed = core_payload::seal(
                            inner.content_key.as_bytes(),
                            &inner.verse_key,
                            &req.side,
                            &key_nonce,
                            b"sidevers/v1/verse-key-share",
                        )?;
                        Ok((
                            inner.verse_key.public_bytes(),
                            token.to_wire_bytes(),
                            key_nonce,
                            sealed,
                        ))
                    })
                    .await?;
                let current_version = contract.version;
                host.with_mut(|inner| {
                    inner.members.insert(req.side);
                    inner.consented_versions.insert(req.side, current_version);
                })
                .await;
                let accept = JoinAcceptPayload {
                    membership_token: token_bytes,
                    key_nonce,
                    sealed_content_key: sealed,
                };
                // The verse signs this envelope, not the host's own side.
                let resp = host
                    .with(|inner| -> Result<_> {
                        Envelope::sign_with(
                            MessageType::JOIN_ACCEPT,
                            &inner.verse_key,
                            Some(env.from),
                            accept.encode(),
                            sidevers_core::envelope::now_unix_seconds()?,
                            random_nonce()?,
                        )
                        .map_err(Error::Core)
                    })
                    .await?;
                let _ = verse_pk;
                send_envelope(&mut send, &resp).await?;
                send.finish().ok();
            }
            MessageType::VERSE_POST => {
                let post = match VersePostPayload::decode(&env.payload) {
                    Ok(p) => p,
                    Err(e) => {
                        warn!("VersePost decode failed: {e}");
                        continue;
                    }
                };
                // Phase 1.5.E: route by env.to (which `post_to_verse`
                // sets to the verse address). Fall back to the default
                // host if to is missing or not hosted. Log the
                // fallback so operators can spot mis-routed posts.
                let host = match env.to.as_ref().and_then(|addr| hosts.get(addr)) {
                    Some(h) => h.clone(),
                    None => {
                        if hosts.len() > 1 {
                            debug!(
                                env_to = ?env.to.as_ref().map(|b| LogId::new(b).to_string()),
                                default = %LogId::new(&default_addr_opt.unwrap_or([0u8; 32])),
                                "VERSE_POST: env.to absent or not hosted; falling through to default verse host (multi-verse routing — likely a sender bug)"
                            );
                        }
                        host.clone()
                    }
                };
                // Only accept posts from current members who have consented
                // to the current contract version.
                let current_version = host.with(|inner| inner.contract.version).await;
                let admit = host
                    .with(|inner| {
                        inner.members.contains(&env.from)
                            && inner
                                .consented_versions
                                .get(&env.from)
                                .is_some_and(|v| *v == current_version)
                    })
                    .await;
                if !admit {
                    debug!("verse post rejected: non-member or stale consent");
                    continue;
                }
                let plain = match host
                    .with(|inner| {
                        inner.content_key.open(
                            &post.nonce,
                            &post.ciphertext,
                            b"sidevers/v1/verse-post",
                        )
                    })
                    .await
                {
                    Ok(p) => p,
                    Err(e) => {
                        warn!("VersePost decrypt failed: {e}");
                        continue;
                    }
                };

                // Fan out the ORIGINAL (still-encrypted) envelope to other
                // active member sessions. We send the original bytes so each
                // recipient verifies the author's signature and decrypts with
                // the same key. Exclude the sender.
                let fan_env = env.clone();
                let host_for_fanout = host.clone();
                let author = env.from;
                tokio::spawn(async move {
                    verse_fanout_post(&host_for_fanout, &fan_env, &author).await;
                });

                // Phase 1.5.D: retain the sealed post so disposition=Retract
                // on a future VerseLeave has something to act on.
                let verse_addr = host.with(|inner| inner.verse_key.public_bytes()).await;
                let now = sidevers_core::envelope::now_unix_seconds().unwrap_or(0);
                host.posts()
                    .insert(verse_addr, env.from, env.clone(), env.payload.clone(), now)
                    .await;

                let _ = services
                    .verse_post_tx
                    .send(VersePostReceived {
                        envelope: env,
                        plaintext: plain,
                    })
                    .await;
                services.metrics.incr_verse_post_received();
            }
            MessageType::VERSE_LEAVE => {
                // Decode + verify membership_hash matches a known member.
                let leave = match VerseLeavePayload::decode(&env.payload) {
                    Ok(l) => l,
                    Err(e) => {
                        warn!("VerseLeave decode failed: {e}");
                        continue;
                    }
                };
                // The leaving side must match the envelope's `from`.
                if leave.side != env.from {
                    warn!("VerseLeave: side != envelope.from");
                    continue;
                }
                // Phase 1.5.E route to the named verse, not the default.
                let host = match hosts.get(&leave.verse) {
                    Some(h) => h.clone(),
                    None => {
                        debug!(
                            "VerseLeave for verse {} not hosted on this node; ignoring",
                            LogId::new(&leave.verse)
                        );
                        continue;
                    }
                };
                let was_member = host
                    .with_mut(|inner| {
                        let was = inner.members.remove(&leave.side);
                        inner.consented_versions.remove(&leave.side);
                        inner.active_sessions.remove(&leave.side);
                        was
                    })
                    .await;
                if !was_member {
                    debug!("VerseLeave from non-member ignored");
                    continue;
                }
                // Phase 1.5.D execute disposition.
                if leave.disposition == DataDisposition::Retract {
                    let verse_addr = host.with(|inner| inner.verse_key.public_bytes()).await;
                    let n = host
                        .posts()
                        .retract_by_author(&verse_addr, &leave.side)
                        .await;
                    debug!(
                        author = %LogId::new(&leave.side),
                        retracted = n,
                        "verse leave disposition=Retract: dropped author's posts"
                    );
                }
                // Rotate the content key and push the new sealed key to
                // every remaining active member session.
                if let Err(e) = rotate_and_push_verse_key(&host).await {
                    warn!("verse key rotation push failed: {e}");
                }
            }
            MessageType::VERSE_REMOVE => {
                let remove = match VerseRemovePayload::decode(&env.payload) {
                    Ok(r) => r,
                    Err(e) => {
                        warn!("VerseRemove decode failed: {e}");
                        continue;
                    }
                };
                // Phase 1.5.E route to the named verse.
                let host = match hosts.get(&remove.verse) {
                    Some(h) => h.clone(),
                    None => {
                        debug!(
                            "VerseRemove for verse {} not hosted on this node; ignoring",
                            LogId::new(&remove.verse)
                        );
                        continue;
                    }
                };
                // Phase 1.5.B: moderator authority — the verse keypair
                // OR any side listed in `contract.moderators` qualifies.
                // The envelope sender and the `issued_by` field must be
                // the same moderator (no cross-signing).
                let (verse_pk, is_mod) = host
                    .with(|inner| {
                        let v = inner.verse_key.public_bytes();
                        let m = inner.contract.is_moderator(&remove.issued_by);
                        (v, m)
                    })
                    .await;
                if !is_mod {
                    debug!(
                        "VerseRemove issued_by ({}) is neither the verse keypair nor a listed moderator; rejected",
                        LogId::new(&remove.issued_by)
                    );
                    let _ = verse_pk;
                    continue;
                }
                if env.from != remove.issued_by {
                    debug!("VerseRemove envelope.from != issued_by; rejected");
                    continue;
                }
                let was_member = host
                    .with_mut(|inner| {
                        let was = inner.members.remove(&remove.side);
                        inner.consented_versions.remove(&remove.side);
                        inner.active_sessions.remove(&remove.side);
                        was
                    })
                    .await;
                if was_member {
                    if let Err(e) = rotate_and_push_verse_key(&host).await {
                        warn!("verse key rotation push failed: {e}");
                    }
                }
            }
            MessageType::VERSE_RECONSENT => {
                let recon = match VerseReconsentPayload::decode_and_verify(&env.payload, &env.from)
                {
                    Ok(r) => r,
                    Err(e) => {
                        warn!("VerseReconsent decode/verify failed: {e}");
                        continue;
                    }
                };
                let updated = host
                    .with_mut(|inner| {
                        if !inner.members.contains(&env.from) {
                            return false;
                        }
                        if recon.contract_hash != inner.contract.hash() {
                            return false;
                        }
                        inner
                            .consented_versions
                            .insert(env.from, inner.contract.version);
                        true
                    })
                    .await;
                if !updated {
                    debug!("VerseReconsent: non-member or stale contract_hash");
                }
            }
            other => {
                debug!("verse server: ignoring 0x{:02X}", other.0);
            }
        }
    }
}

/// RAII cleanup for a Verse-intent session: remove from active_sessions.
struct VerseSessionGuard {
    host: crate::verse::VerseHost,
    peer_side: [u8; 32],
}

impl Drop for VerseSessionGuard {
    fn drop(&mut self) {
        let host = self.host.clone();
        let key = self.peer_side;
        tokio::spawn(async move {
            host.with_mut(|inner| {
                inner.active_sessions.remove(&key);
            })
            .await;
        });
    }
}

/// Fan a verse post out to every other active member session.
async fn verse_fanout_post(host: &crate::verse::VerseHost, env: &Envelope, author: &[u8; 32]) {
    let connections: Vec<([u8; 32], quinn::Connection)> = host
        .with(|inner| {
            inner
                .active_sessions
                .iter()
                .filter(|(side, _)| *side != author && inner.members.contains(*side))
                .map(|(k, c)| (*k, c.clone()))
                .collect()
        })
        .await;
    for (peer, conn) in connections {
        let env = env.clone();
        tokio::spawn(async move {
            if let Ok((mut send, _recv)) = conn.open_bi().await {
                if send_envelope(&mut send, &env).await.is_ok() {
                    send.finish().ok();
                }
            }
            let _ = peer;
        });
    }
}

/// Rotate the verse content key and push the new sealed key to every
/// remaining active member session as a `JOIN_ACCEPT`-shaped envelope.
async fn rotate_and_push_verse_key(host: &crate::verse::VerseHost) -> Result<()> {
    host.rotate_content_key().await.map_err(Error::Core)?;

    // Snapshot of (member_side, connection, sealed_key, key_nonce, signed_env).
    // Build one JoinAccept envelope per member; the membership token is also
    // refreshed under the current contract hash.
    let pushes: Vec<([u8; 32], quinn::Connection, Envelope)> = host
        .with(|inner| -> Result<_> {
            let mut out = Vec::new();
            let now = sidevers_core::envelope::now_unix_seconds()?;
            for (member_side, conn) in inner.active_sessions.iter() {
                if !inner.members.contains(member_side) {
                    continue;
                }
                let token = MembershipToken::sign(
                    &inner.verse_key,
                    inner.contract.hash(),
                    *member_side,
                    now,
                )?;
                let key_nonce = random_nonce()?;
                let sealed = core_payload::seal(
                    inner.content_key.as_bytes(),
                    &inner.verse_key,
                    member_side,
                    &key_nonce,
                    b"sidevers/v1/verse-key-share",
                )?;
                let payload = JoinAcceptPayload {
                    membership_token: token.to_wire_bytes(),
                    key_nonce,
                    sealed_content_key: sealed,
                };
                let env = Envelope::sign_with(
                    MessageType::JOIN_ACCEPT,
                    &inner.verse_key,
                    Some(*member_side),
                    payload.encode(),
                    now,
                    random_nonce()?,
                )?;
                out.push((*member_side, conn.clone(), env));
            }
            Ok(out)
        })
        .await?;

    for (member, conn, env) in pushes {
        let host = host.clone();
        tokio::spawn(async move {
            // Audit P1.D — try to deliver; on any failure (member offline,
            // stream error, transient blip) stash the envelope so the
            // next inbound contact from `member` re-pushes the rotated
            // key. Idempotent: storing the same envelope twice is fine,
            // and the most-recent stash supersedes any earlier one.
            let delivered = match conn.open_bi().await {
                Ok((mut send, _recv)) => match send_envelope(&mut send, &env).await {
                    Ok(()) => {
                        send.finish().ok();
                        true
                    }
                    Err(_) => false,
                },
                Err(_) => false,
            };
            if !delivered {
                debug!(
                    member = %LogId::new(&member),
                    "verse key rotation push failed; stashed for redelivery on reconnect"
                );
                host.stash_pending_key_push(member, env).await;
            }
        });
    }
    Ok(())
}

/// RAII helper: on drop, remove the registered gossip connection. We must
/// remove on every exit path (error, success, drop). Without `scopeguard`,
/// hand-roll a Drop-based guard.
struct GossipGuard {
    active: Arc<Mutex<HashMap<[u8; 32], quinn::Connection>>>,
    key: [u8; 32],
}

impl Drop for GossipGuard {
    fn drop(&mut self) {
        let active = self.active.clone();
        let key = self.key;
        tokio::spawn(async move {
            let mut g = active.lock().await;
            g.remove(&key);
        });
    }
}

fn scopeguard_gossip(
    active: Arc<Mutex<HashMap<[u8; 32], quinn::Connection>>>,
    key: [u8; 32],
) -> GossipGuard {
    GossipGuard { active, key }
}

/// Fan a novel public broadcast to other active gossip connections,
/// gated by the configured `GossipPolicy` (Phase 1.A3, spec §6.9.3).
async fn fanout_broadcast(services: &Services, env: &Envelope, source_peer: &[u8; 32]) {
    let policy = *services.gossip_policy.lock().await;
    let mut connections: Vec<([u8; 32], quinn::Connection)> = {
        let active = services.active_gossip.lock().await;
        active
            .iter()
            .filter(|(k, _)| *k != source_peer)
            .map(|(k, c)| (*k, c.clone()))
            .collect()
    };
    // Apply the policy filter.
    match policy.propagation {
        GossipPropagation::Open => {}
        GossipPropagation::ExcludeRefused => {
            let mut kept = Vec::with_capacity(connections.len());
            for (peer_key, conn) in connections.drain(..) {
                if services.reputation.is_refused(&peer_key).await {
                    debug!(
                        peer = %LogId::new(&peer_key),
                        "gossip-policy: skipping refused peer in fanout"
                    );
                    continue;
                }
                kept.push((peer_key, conn));
            }
            connections = kept;
        }
        GossipPropagation::RelationshipsOnly => {
            let mut kept = Vec::with_capacity(connections.len());
            for (peer_key, conn) in connections.drain(..) {
                if !services.side_state.relationship_contains(&peer_key).await {
                    debug!(
                        peer = %LogId::new(&peer_key),
                        "gossip-policy: skipping non-relationship peer in fanout"
                    );
                    continue;
                }
                kept.push((peer_key, conn));
            }
            connections = kept;
        }
    }
    for (peer_key, conn) in connections {
        let env = env.clone();
        tokio::spawn(async move {
            // §7.6: small randomized jitter so a side's republish cadence
            // doesn't fingerprint the operator. Disabled in tests via
            // SIDEVERS_DISABLE_JITTER=1.
            apply_publish_jitter().await;
            // Best-effort: open a new bi-stream, send envelope, finish. Errors
            // here just mean the peer dropped or is closing — fine.
            if let Ok((mut send, _recv)) = conn.open_bi().await {
                if send_envelope(&mut send, &env).await.is_ok() {
                    send.finish().ok();
                }
            }
            let _ = peer_key;
        });
    }
}

async fn build_storage_response(
    side: &SideKey,
    peer_side: &[u8; 32],
    store: &ObjectStore,
    req: &StorageGetPayload,
) -> Result<Envelope> {
    let bytes_opt: Result<Option<Vec<u8>>, _> = match &req.range {
        Some(r) => store.get_range(&req.hash, r.start..r.end).await,
        None => store.get(&req.hash).await,
    };
    match bytes_opt {
        Ok(Some(bytes)) => {
            let payload = StorageHavePayload {
                hash: req.hash,
                bytes,
                final_: true,
            };
            sign_response(side, peer_side, MessageType::STORAGE_HAVE, payload.encode())
        }
        Ok(None) => {
            let payload = StorageMissPayload {
                hash: req.hash,
                hints: vec![],
            };
            sign_response(side, peer_side, MessageType::STORAGE_MISS, payload.encode())
        }
        Err(e) => {
            warn!("storage get failed: {e}");
            let payload = StorageMissPayload {
                hash: req.hash,
                hints: vec![],
            };
            sign_response(side, peer_side, MessageType::STORAGE_MISS, payload.encode())
        }
    }
}

fn sign_response(
    side: &SideKey,
    peer_side: &[u8; 32],
    mt: MessageType,
    payload: Vec<u8>,
) -> Result<Envelope> {
    let env = Envelope::sign_with(
        mt,
        side,
        Some(*peer_side),
        payload,
        sidevers_core::envelope::now_unix_seconds()?,
        random_nonce()?,
    )?;
    Ok(env)
}

async fn check_freshness_and_replay_metered(
    env: &Envelope,
    replay: &Arc<Mutex<ReplayCache>>,
    metrics: Option<&Metrics>,
) -> bool {
    let now = match sidevers_core::envelope::now_unix_seconds() {
        Ok(n) => n,
        Err(_) => return false,
    };
    // Phase 1.H1 graceful fallback: tiered skew handling.
    //   |skew| ≤ DEFAULT (300s)        → accept silently
    //   |skew| in (DEFAULT, SOFT]      → accept with warning so operators
    //                                    notice clock drift (mine or peer's)
    //                                    instead of silently dropping all
    //                                    traffic.
    //   |skew| > SOFT (900s)           → reject (catastrophic skew).
    let skew = env.timestamp.abs_diff(now);
    if skew > sidevers_core::envelope::SOFT_MAX_SKEW_SECS {
        if let Some(m) = metrics {
            m.incr_dropped_skew_hard();
            m.incr_dropped_freshness();
        }
        return false;
    }
    if skew > sidevers_core::envelope::DEFAULT_MAX_SKEW_SECS {
        if let Some(m) = metrics {
            m.incr_warned_skew_soft();
        }
        warn!(
            from = %LogId::new(&env.from),
            skew_secs = skew,
            "clock-skew warning: envelope outside default window but within soft limit — check local clock"
        );
    }
    let mut nonce_arr = [0u8; NONCE_LEN];
    nonce_arr.copy_from_slice(&env.nonce);
    let mut cache = replay.lock().await;
    let is_replay = cache.observe(now, &env.from, &nonce_arr);
    if is_replay && let Some(m) = metrics {
        m.incr_dropped_replay();
    }
    !is_replay
}

/// Per spec §6.9: consult the per-peer reputation table BEFORE doing any
/// expensive per-envelope work. Returns `false` if `env.from` is currently
/// refused (sig-failures or malformed-payload threshold crossed) OR if the
/// peer has exhausted its per-second token bucket. Increments the seen
/// counter regardless. Also bumps the H3 envelope counters.
async fn check_reputation_gate(env: &Envelope, services: &Services) -> bool {
    services.metrics.incr_envelope();
    let now = sidevers_core::envelope::now_unix_seconds().unwrap_or(0);
    let ok = services.reputation.observe_envelope(&env.from, now).await;
    if !ok {
        services.metrics.incr_dropped_reputation();
    }
    ok
}

/// Stamp the hosted side's `last_send_at = now` and, if the lifecycle is
/// still `Created`, advance it to `Active`. Retirement is sticky: once
/// the lifecycle is `Retired`, this is a no-op for that field. Used by
/// the Node wrapper methods (`Node::send_dm`, etc.) so outbound activity
/// transitions the side from Created → Active automatically.
async fn touch_local_send(services: &Services) {
    services.side_state.touch_send().await;
}

/// Per spec §7.8: warn (but don't drop) when an inbound envelope is signed
/// by a side this node has marked retired. Called after signature
/// verification, before normal processing.
async fn check_retirement(env: &Envelope, services: &Services) {
    if services.side_state.is_retired_seen(&env.from).await {
        warn!(
            "anomalous: signature from retired side {}",
            LogId::new(&env.from)
        );
    }
}

/// Decide whether this node will accept a `token`-requiring message from
/// `sender`. Three-tier lookup, per spec §7.4 + §7.7:
///
///   1. If a relationship exists for `sender`, the relationship's
///      capability set is authoritative. An empty set is a *block*.
///      (§7.4: "Capabilities are local policy.")
///   2. Otherwise, if a local profile is installed, its capability set
///      decides. (§7.7.)
///   3. Otherwise, fall back to a permissive default
///      `{direct-message, storage-host, gossip-relay}` so out-of-the-box
///      nodes (and the existing test suite) keep working.
async fn capability_allows(services: &Services, sender: &[u8; 32], token: &str) -> bool {
    if let Some(r) = services.side_state.get_relationship(sender).await {
        return r.capabilities.contains(token);
    }
    match services.side_state.profile().await {
        Some(p) => p.has_capability(token),
        None => {
            token == profile_msg::capability::DIRECT_MESSAGE
                || token == profile_msg::capability::STORAGE_HOST
                || token == profile_msg::capability::GOSSIP_RELAY
        }
    }
}

// =============================================================================
// Client-side helpers (used by the CLI and conformance harness).
// =============================================================================

/// Ask a Gossip-intent peer for known peers it has. Returns whatever it sends.
pub async fn query_peers(
    session: &Session,
    side: &SideKey,
    limit: u64,
    intent_filter: Option<u8>,
) -> Result<Vec<PeerInfo>> {
    let req = PeerAskPayload {
        limit,
        intent_filter,
    };
    let env = sign_response(
        side,
        &session.peer_side,
        MessageType::PEER_ASK,
        req.encode(),
    )?;
    let (mut send, mut recv) = session.open_and_send(&env).await?;
    send.finish().ok();
    let resp = recv_envelope(&mut recv).await?;
    if resp.message_type != MessageType::PEER_TELL {
        return Err(Error::Invariant("expected PeerTell"));
    }
    let tell = PeerTellPayload::decode(&resp.payload).map_err(Error::Core)?;
    Ok(tell.peers)
}

/// Ask a Gossip-intent peer (acting as a rendezvous broker) for endpoints
/// of `target`. Returns whatever the broker says.
pub async fn request_rendezvous(
    session: &Session,
    side: &SideKey,
    target: [u8; 32],
) -> Result<Vec<String>> {
    let req = RendezvousPayload { target };
    let env = sign_response(
        side,
        &session.peer_side,
        MessageType::RENDEZVOUS,
        req.encode(),
    )?;
    let (mut send, mut recv) = session.open_and_send(&env).await?;
    send.finish().ok();
    let resp = recv_envelope(&mut recv).await?;
    if resp.message_type != MessageType::RENDEZVOUS_ACK {
        return Err(Error::Invariant("expected RendezvousAck"));
    }
    let ack = RendezvousAckPayload::decode(&resp.payload).map_err(Error::Core)?;
    if ack.target != target {
        return Err(Error::Invariant("RendezvousAck target mismatch"));
    }
    Ok(ack.endpoints)
}

/// Submit an outer envelope for store-and-forward. The forwarder will hold
/// it for `recipient` for at most `ttl_secs` seconds.
pub async fn submit_forward(
    session: &Session,
    side: &SideKey,
    recipient: [u8; 32],
    envelope: Vec<u8>,
    ttl_secs: u64,
) -> Result<()> {
    let req = ForwardStorePayload {
        envelope,
        recipient,
        ttl_secs,
    };
    let env = sign_response(
        side,
        &session.peer_side,
        MessageType::FORWARD_STORE,
        req.encode(),
    )?;
    let (mut send, _recv) = session.open_and_send(&env).await?;
    send.finish().ok();
    let _ = send.stopped().await;
    Ok(())
}

/// Publish a broadcast envelope on this gossip session. The peer (acting as a
/// gossip relay) is expected to dedup and propagate. Per §7.6, the call
/// applies a small randomized jitter before the actual send so a side's
/// publish cadence doesn't fingerprint its operator. Disabled in tests via
/// `SIDEVERS_DISABLE_JITTER=1`.
pub async fn publish_broadcast(session: &Session, side: &SideKey, payload: Vec<u8>) -> Result<()> {
    apply_publish_jitter().await;
    let env = Envelope::sign_with(
        MessageType::ANNOUNCEMENT,
        side,
        None,
        payload,
        sidevers_core::envelope::now_unix_seconds()?,
        random_nonce()?,
    )?;
    let (mut send, _recv) = session.open_and_send(&env).await?;
    send.finish().ok();
    let _ = send.stopped().await;
    Ok(())
}

/// Accept one server-pushed bi-stream on this session and return the envelope
/// it carries. Used by recipients to drain `ForwardDeliver` pushes from their
/// rendezvous broker / forwarder.
pub async fn accept_one_push(session: &Session) -> Result<Envelope> {
    let (_send, _recv, env) = session.accept_one().await?;
    Ok(env)
}

/// Fetch a verse's current contract over an open Verse-intent session.
pub async fn fetch_contract(session: &Session, side: &SideKey) -> Result<ContractObject> {
    let req = ContractFetchPayload { version: None };
    let env = sign_response(
        side,
        &session.peer_side,
        MessageType::CONTRACT_FETCH,
        req.encode(),
    )?;
    let (mut send, mut recv) = session.open_and_send(&env).await?;
    send.finish().ok();
    let resp = crate::framing::recv_envelope(&mut recv).await?;
    if resp.message_type != MessageType::CONTRACT_DELIVER {
        return Err(Error::Invariant("expected ContractDeliver"));
    }
    let deliver = ContractDeliverPayload::decode(&resp.payload).map_err(Error::Core)?;
    Ok(deliver.contract)
}

/// Joined-verse handle returned by `request_join`. Members keep this around
/// to post (the content key) and to prove membership (the token bytes).
#[derive(Debug, Clone)]
pub struct VerseMembership {
    pub verse: [u8; 32],
    pub contract_hash: [u8; 32],
    pub membership_token: Vec<u8>,
    pub content_key: VerseContentKey,
}

/// Send a JoinRequest under the given contract and await a JoinAccept.
/// On success, decrypts the sealed content key and returns a `VerseMembership`
/// the caller can use to post.
pub async fn request_join(
    session: &Session,
    side: &SideKey,
    contract: &ContractObject,
    fields: FieldValues,
) -> Result<VerseMembership> {
    let contract_hash = contract.hash();
    let req = JoinRequestPayload::sign(side, contract_hash, fields)?;
    let env = sign_response(
        side,
        &session.peer_side,
        MessageType::JOIN_REQUEST,
        req.encode(),
    )?;
    let (mut send, mut recv) = session.open_and_send(&env).await?;
    send.finish().ok();
    let resp = crate::framing::recv_envelope(&mut recv).await?;
    match resp.message_type {
        MessageType::JOIN_ACCEPT => {
            let accept = JoinAcceptPayload::decode(&resp.payload).map_err(Error::Core)?;
            // Verify the embedded membership token against the verse's pubkey.
            let token =
                MembershipToken::from_wire_bytes(&accept.membership_token).map_err(Error::Core)?;
            if token.verse != contract.verse {
                return Err(Error::Invariant("membership-token verse mismatch"));
            }
            if token.contract_hash != contract_hash {
                return Err(Error::Invariant("membership-token contract mismatch"));
            }
            // Decrypt the content key (verse → joining-side, X25519 ECDH).
            let plain = core_payload::open(
                &accept.sealed_content_key,
                side,
                &contract.verse,
                &accept.key_nonce,
                b"sidevers/v1/verse-key-share",
            )?;
            if plain.len() != 32 {
                return Err(Error::Invariant("verse content key not 32 bytes"));
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&plain);
            Ok(VerseMembership {
                verse: contract.verse,
                contract_hash,
                membership_token: accept.membership_token,
                content_key: VerseContentKey::from_bytes(key),
            })
        }
        MessageType::JOIN_DECLINE => {
            let decline = JoinDeclinePayload::decode(&resp.payload).map_err(Error::Core)?;
            Err(Error::Invariant(match decline.reason.as_str() {
                "contract-version-mismatch" => "join declined: contract-version-mismatch",
                "missing-required" => "join declined: missing-required",
                "forbidden-field" => "join declined: forbidden-field",
                "moderator-rejected" => "join declined: moderator-rejected",
                _ => "join declined",
            }))
        }
        _ => Err(Error::Invariant("unexpected join response")),
    }
}

/// Announce departure to the verse. The host removes us from members and
/// rotates the content key. `disposition` is advisory per spec §8.8.
pub async fn leave_verse(
    session: &Session,
    side: &SideKey,
    membership: &VerseMembership,
    disposition: DataDisposition,
    reason: Option<String>,
) -> Result<()> {
    let membership_hash = *blake3::hash(&membership.membership_token).as_bytes();
    let payload =
        VerseLeavePayload::sign(side, membership.verse, membership_hash, reason, disposition)?;
    let env = Envelope::sign_with(
        MessageType::VERSE_LEAVE,
        side,
        Some(membership.verse),
        payload.encode(),
        sidevers_core::envelope::now_unix_seconds()?,
        random_nonce()?,
    )?;
    let (mut send, _recv) = session.open_and_send(&env).await?;
    send.finish().ok();
    let _ = send.stopped().await;
    Ok(())
}

/// Re-consent to a new contract version. The member's `side` must be the one
/// the host has on record; the `new_contract_hash` must match the host's
/// current contract.
pub async fn reconsent_to_amendment(
    session: &Session,
    side: &SideKey,
    new_contract_hash: [u8; 32],
) -> Result<()> {
    let payload = VerseReconsentPayload::sign(side, new_contract_hash)?;
    let env = Envelope::sign_with(
        MessageType::VERSE_RECONSENT,
        side,
        Some(session.peer_side),
        payload.encode(),
        sidevers_core::envelope::now_unix_seconds()?,
        random_nonce()?,
    )?;
    let (mut send, _recv) = session.open_and_send(&env).await?;
    send.finish().ok();
    let _ = send.stopped().await;
    Ok(())
}

/// Decode a server-pushed `VERSE_AMEND` envelope into the new contract.
/// The envelope's `from` MUST match `expected_verse_pubkey` (i.e. the
/// verse's own keypair from the recipient's `VerseMembership`).
pub fn decode_verse_amend(
    push: &Envelope,
    expected_verse_pubkey: &[u8; 32],
) -> Result<ContractObject> {
    if push.message_type != MessageType::VERSE_AMEND {
        return Err(Error::Invariant("expected VERSE_AMEND envelope"));
    }
    if push.from != *expected_verse_pubkey {
        return Err(Error::Invariant("VerseAmend not signed by the verse"));
    }
    use sidevers_core::messages::verse::VerseAmendPayload;
    let payload = VerseAmendPayload::decode(&push.payload).map_err(Error::Core)?;
    // Inner contract's `verse` field must also match.
    if payload.contract.verse != *expected_verse_pubkey {
        return Err(Error::Invariant("VerseAmend contract.verse mismatch"));
    }
    Ok(payload.contract)
}

/// Apply a server-pushed `JOIN_ACCEPT`-shaped envelope as a key-rotation
/// update for an existing membership: replace the content key, refresh the
/// membership token. The verse keypair (signed envelope's `from`) is checked
/// against the membership's recorded verse address.
pub fn apply_verse_key_rotation(
    member_side: &SideKey,
    membership: &mut VerseMembership,
    push: &Envelope,
) -> Result<()> {
    if push.from != membership.verse {
        return Err(Error::Invariant("rotation push: from != verse"));
    }
    let accept = JoinAcceptPayload::decode(&push.payload).map_err(Error::Core)?;
    let plain = core_payload::open(
        &accept.sealed_content_key,
        member_side,
        &membership.verse,
        &accept.key_nonce,
        b"sidevers/v1/verse-key-share",
    )?;
    if plain.len() != 32 {
        return Err(Error::Invariant("verse content key not 32 bytes"));
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&plain);
    membership.content_key = VerseContentKey::from_bytes(key_bytes);
    membership.membership_token = accept.membership_token;
    Ok(())
}

/// Post a plain-text payload to a verse. The content is encrypted with the
/// verse content key the member received at join time.
pub async fn post_to_verse(
    session: &Session,
    member_side: &SideKey,
    membership: &VerseMembership,
    body: &[u8],
) -> Result<()> {
    let (nonce, ciphertext) = membership
        .content_key
        .seal(body, b"sidevers/v1/verse-post")?;
    let payload = VersePostPayload { nonce, ciphertext };
    let env = Envelope::sign_with(
        MessageType::VERSE_POST,
        member_side,
        Some(membership.verse),
        payload.encode(),
        sidevers_core::envelope::now_unix_seconds()?,
        random_nonce()?,
    )?;
    let (mut send, _recv) = session.open_and_send(&env).await?;
    send.finish().ok();
    let _ = send.stopped().await;
    Ok(())
}

/// Send a single DirectMessage on this session. Finishes the send half and
/// awaits the peer's stream-close acknowledgment before returning — without
/// this, the caller can drop the session before the bytes leave the local
/// QUIC stack.
///
/// # Errors
/// - `Error::Core` for envelope-sign / payload-seal failures (CSPRNG /
///   AEAD / clock).
/// - Underlying `quinn` stream errors via `From` (`Error::Write`,
///   `Error::Connection`).
pub async fn send_dm(session: &Session, side: &SideKey, plaintext: &[u8]) -> Result<()> {
    let nonce = random_nonce()?;
    let ciphertext = core_payload::seal(plaintext, side, &session.peer_side, &nonce, b"")?;
    let env = Envelope::sign_with(
        MessageType::DIRECT_MESSAGE,
        side,
        Some(session.peer_side),
        ciphertext,
        sidevers_core::envelope::now_unix_seconds()?,
        nonce,
    )?;
    let (mut send, _recv) = session.open_and_send(&env).await?;
    send.finish().ok();
    // Wait for the peer to either STOP_SENDING (abnormal) or fully read +
    // close (normal). Either way, the bytes have left our side by then.
    let _ = send.stopped().await;
    Ok(())
}

/// Publish a signed `LinkageProof` to the peer over an existing
/// Direct-intent session (spec §2.7). `side` must be one of the two
/// linked sides — the responder rejects proofs whose envelope sender is
/// neither `proof.side_a` nor `proof.side_b`.
///
/// # Errors
/// - `Error::Core` for envelope-sign failures.
/// - Underlying `quinn` stream errors via `From`.
pub async fn publish_linkage_proof(
    session: &Session,
    side: &SideKey,
    proof: &LinkageProof,
) -> Result<()> {
    let env = Envelope::sign_with(
        MessageType::LINKAGE_PUBLISH,
        side,
        Some(session.peer_side),
        proof.to_wire_bytes(),
        now_unix_seconds()?,
        random_nonce()?,
    )?;
    let (mut send, _recv) = session.open_and_send(&env).await?;
    send.finish().ok();
    let _ = send.stopped().await;
    Ok(())
}

/// Offer a content-addressed object to a peer over a Storage-intent
/// session. The peer replies with a `StorageWant` indicating whether they
/// want the bytes; if they do, we send them on the same stream.
///
/// Returns `Ok(true)` if the peer wanted (and we sent) the bytes,
/// `Ok(false)` if they declined (e.g., they already had it).
pub async fn offer_object(
    session: &Session,
    side: &SideKey,
    reference: sidevers_storage::Reference,
    store: &sidevers_storage::ObjectStore,
) -> Result<bool> {
    use crate::storage_protocol::StorageOfferPayload;
    let offer = StorageOfferPayload {
        reference: reference.clone(),
    };
    let env = sign_response(
        side,
        &session.peer_side,
        MessageType::STORAGE_OFFER,
        offer.encode(),
    )?;
    let (mut send, mut recv) = session.open_and_send(&env).await?;

    let resp = crate::framing::recv_envelope(&mut recv).await?;
    if resp.message_type != MessageType::STORAGE_WANT {
        send.finish().ok();
        return Err(Error::Invariant("expected StorageWant"));
    }
    let want =
        crate::storage_protocol::StorageWantPayload::decode(&resp.payload).map_err(Error::Core)?;
    if want.hash != reference.hash {
        send.finish().ok();
        return Err(Error::Invariant("StorageWant hash mismatch"));
    }
    if !want.want {
        send.finish().ok();
        return Ok(false);
    }
    // Peer wants it — fetch locally + push.
    let bytes = match store.get(&reference.hash).await? {
        Some(b) => b,
        None => {
            send.finish().ok();
            return Err(Error::Invariant("offer_object: object not in local store"));
        }
    };
    let have = StorageHavePayload {
        hash: reference.hash,
        bytes,
        final_: true,
    };
    let have_env = sign_response(
        side,
        &session.peer_side,
        MessageType::STORAGE_HAVE,
        have.encode(),
    )?;
    send_envelope(&mut send, &have_env).await?;
    send.finish().ok();
    let _ = send.stopped().await;
    Ok(true)
}

/// Fetch the signed profile (§7.3) of the peer on this Direct session.
/// Sends `PROFILE_FETCH` carrying the target's pubkey, awaits
/// `PROFILE_DELIVER` on the same bidi stream, and verifies the embedded
/// signature. The returned profile is content-addressed: callers can
/// cache by `profile.hash()`.
///
/// # Errors
/// - `Error::Invariant` if the peer responds with anything other than
///   `PROFILE_DELIVER`, or if the profile's `side` field doesn't match
///   `target` or the envelope's `from`.
/// - `Error::Core` if the profile signature fails to verify.
/// - Underlying `quinn` stream errors via `From`.
pub async fn fetch_profile(
    session: &Session,
    side: &SideKey,
    target: [u8; 32],
) -> Result<ProfilePayload> {
    let env = sign_response(
        side,
        &session.peer_side,
        MessageType::PROFILE_FETCH,
        target.to_vec(),
    )?;
    let (mut send, mut recv) = session.open_and_send(&env).await?;
    send.finish().ok();

    let resp = crate::framing::recv_envelope(&mut recv).await?;
    if resp.message_type != MessageType::PROFILE_DELIVER {
        return Err(Error::Invariant("expected PROFILE_DELIVER"));
    }
    let profile = ProfilePayload::from_wire_bytes(&resp.payload).map_err(Error::Core)?;
    if profile.side != target {
        return Err(Error::Invariant("PROFILE_DELIVER: profile.side != target"));
    }
    if profile.side != resp.from {
        return Err(Error::Invariant(
            "PROFILE_DELIVER: profile.side != env.from",
        ));
    }
    Ok(profile)
}

/// Send a signed `SideRetirement` record (§7.8) to the peer on this Direct
/// session. The peer marks the side as retired locally and surfaces a
/// warning on any subsequent signature from it.
pub async fn announce_retirement(
    session: &Session,
    side: &SideKey,
    record: &SideRetirementPayload,
) -> Result<()> {
    let env = sign_response(
        side,
        &session.peer_side,
        MessageType::SIDE_RETIREMENT,
        record.to_wire_bytes(),
    )?;
    let (mut send, _recv) = session.open_and_send(&env).await?;
    send.finish().ok();
    let _ = send.stopped().await;
    Ok(())
}

/// Send a signed `StorageRetract` for an object the local side previously
/// published. Honest peers receiving this stop serving the bytes.
pub async fn retract_object(session: &Session, side: &SideKey, hash: [u8; 32]) -> Result<()> {
    let payload = crate::storage_protocol::StorageRetractPayload { hash };
    let env = sign_response(
        side,
        &session.peer_side,
        MessageType::STORAGE_RETRACT,
        payload.encode(),
    )?;
    let (mut send, _recv) = session.open_and_send(&env).await?;
    send.finish().ok();
    let _ = send.stopped().await;
    Ok(())
}

/// Fetch an object by hash from this storage session.
///
/// # Errors
/// - `Error::Invariant` if the peer's response is not `STORAGE_HAVE` or
///   `STORAGE_MISS`, or if a `STORAGE_HAVE` response's bytes hash to a
///   value that doesn't match the requested hash (§5.4 mandate).
/// - Underlying `quinn` stream / `Core` errors via `From`.
pub async fn fetch_object(
    session: &Session,
    side: &SideKey,
    hash: &[u8; ADDRESS_LEN],
) -> Result<Option<Vec<u8>>> {
    let req = StorageGetPayload {
        hash: *hash,
        range: None,
    };
    let env = sign_response(
        side,
        &session.peer_side,
        MessageType::STORAGE_GET,
        req.encode(),
    )?;
    let (mut send, mut recv) = session.open_and_send(&env).await?;
    send.finish().ok();

    let resp = crate::framing::recv_envelope(&mut recv).await?;
    match resp.message_type {
        MessageType::STORAGE_HAVE => {
            let have = StorageHavePayload::decode(&resp.payload).map_err(Error::Core)?;
            // Hash-on-fetch verification — spec §5.4 mandate.
            let got = blake3::hash(&have.bytes);
            if got.as_bytes() != hash {
                return Err(Error::Invariant("storage have: hash mismatch"));
            }
            Ok(Some(have.bytes))
        }
        MessageType::STORAGE_MISS => Ok(None),
        _ => Err(Error::Invariant("unexpected storage response")),
    }
}
