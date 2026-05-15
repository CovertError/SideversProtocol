//! Top-level node glue: accepts incoming connections, runs the responder
//! handshake, dispatches by intent. Also offers a `dial` method that runs
//! the initiator handshake and returns a `Session`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use sidevers_core::Envelope;
use sidevers_core::envelope::{NONCE_LEN, random_nonce};
use sidevers_core::keys::SideKey;
use sidevers_core::messages::forward::{ForwardDeliverPayload, ForwardStorePayload};
use sidevers_core::messages::peer::{PeerAskPayload, PeerInfo, PeerTellPayload};
use sidevers_core::messages::rendezvous::{RendezvousAckPayload, RendezvousPayload};
use sidevers_core::messages::verse::{
    ContractDeliverPayload, ContractFetchPayload, DataDisposition, FieldValues, JoinAcceptPayload,
    JoinDeclinePayload, JoinRequestPayload, VerseLeavePayload, VersePostPayload,
    VerseReconsentPayload, VerseRemovePayload,
};
use sidevers_core::payload as core_payload;
use sidevers_core::replay::ReplayCache;
use sidevers_core::verse::{ContractObject, MembershipToken, VerseContentKey};
use sidevers_core::{Address, AddressKind, MessageType};
use sidevers_storage::ObjectStore;
use sidevers_storage::object::ADDRESS_LEN;
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use crate::error::{Error, Result};
use crate::forward::Mailbox;
use crate::framing::{recv_envelope, send_envelope};
use crate::gossip::GossipState;
use crate::handshake::{run_initiator, run_responder};
use crate::peers::{PeerTable, unix_now};
use crate::session::{Intent, Session};
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

/// Per-node services threaded through the accept loop and handlers.
#[derive(Clone)]
struct Services {
    side: Arc<SideKey>,
    store: ObjectStore,
    replay: Arc<Mutex<ReplayCache>>,
    peers: PeerTable,
    mailbox: Mailbox,
    gossip: GossipState,
    /// Currently-active inbound gossip sessions — used to fan novel
    /// broadcasts out to subscribers. Keyed on the peer's side public key.
    active_gossip: Arc<Mutex<HashMap<[u8; 32], quinn::Connection>>>,
    /// Optional: a verse this node hosts. Phase 1.5a allows at most one.
    hosted_verse: Arc<Mutex<Option<VerseHost>>>,
    dm_tx: mpsc::Sender<DirectMessageReceived>,
    gossip_tx: mpsc::Sender<Envelope>,
    verse_post_tx: mpsc::Sender<VersePostReceived>,
}

pub struct Node {
    endpoint: quinn::Endpoint,
    services: Services,
    listen_addr: SocketAddr,
    dm_rx: Mutex<mpsc::Receiver<DirectMessageReceived>>,
    gossip_rx: Mutex<mpsc::Receiver<Envelope>>,
    verse_post_rx: Mutex<mpsc::Receiver<VersePostReceived>>,
    accept_handle: JoinHandle<()>,
}

impl Node {
    /// Start a node bound at `listen_addr`. Returns once the QUIC endpoint
    /// is listening and the accept loop is spawned.
    pub async fn start(side: SideKey, listen_addr: SocketAddr, data_dir: &Path) -> Result<Self> {
        let endpoint = build_server_endpoint(listen_addr)?;
        let local = endpoint.local_addr()?;
        let store = ObjectStore::open(data_dir).await?;
        let side = Arc::new(side);
        let replay = Arc::new(Mutex::new(ReplayCache::new()));
        let peers = PeerTable::default();
        let mailbox = Mailbox::new();
        let gossip = GossipState::new();

        let (dm_tx, dm_rx) = mpsc::channel::<DirectMessageReceived>(128);
        let (gossip_tx, gossip_rx) = mpsc::channel::<Envelope>(128);
        let (verse_post_tx, verse_post_rx) = mpsc::channel::<VersePostReceived>(128);

        let services = Services {
            side,
            store,
            replay,
            peers,
            mailbox,
            gossip,
            active_gossip: Arc::new(Mutex::new(HashMap::new())),
            hosted_verse: Arc::new(Mutex::new(None)),
            dm_tx,
            gossip_tx,
            verse_post_tx,
        };

        let accept_handle = tokio::spawn(accept_loop(endpoint.clone(), services.clone()));

        Ok(Self {
            endpoint,
            services,
            listen_addr: local,
            dm_rx: Mutex::new(dm_rx),
            gossip_rx: Mutex::new(gossip_rx),
            verse_post_rx: Mutex::new(verse_post_rx),
            accept_handle,
        })
    }

    /// Register a hosted verse with this node. Verse-intent connections from
    /// peers will be served using this state. Phase 1.5a allows at most one.
    pub async fn host_verse(&self, verse: VerseHost) {
        let mut g = self.services.hosted_verse.lock().await;
        *g = Some(verse);
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
        let host = {
            let g = self.services.hosted_verse.lock().await;
            match g.as_ref() {
                Some(h) => h.clone(),
                None => return Err(Error::Invariant("no hosted verse to amend")),
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
    }
}

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

async fn handle_connection(conn: quinn::Connection, services: Services) -> Result<()> {
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

async fn serve_direct(session: Session, services: Services) -> Result<()> {
    loop {
        let (_send, _recv, env) = match session.accept_one().await {
            Ok(triple) => triple,
            Err(Error::Connection(quinn::ConnectionError::ApplicationClosed(_)))
            | Err(Error::Connection(quinn::ConnectionError::ConnectionClosed(_)))
            | Err(Error::Connection(quinn::ConnectionError::LocallyClosed))
            | Err(Error::Connection(quinn::ConnectionError::TimedOut)) => return Ok(()),
            Err(e) => return Err(e),
        };
        if !check_freshness_and_replay(&env, &services.replay).await {
            warn!("dm rejected: stale or replayed");
            continue;
        }
        if env.message_type != MessageType::DIRECT_MESSAGE {
            continue;
        }
        let plaintext =
            match core_payload::open(&env.payload, &services.side, &env.from, &env.nonce, b"") {
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
    }
}

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
        if !check_freshness_and_replay(&env, &services.replay).await {
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
                    }
                    Ok(_) => warn!("storage offer: ingested hash mismatch"),
                    Err(e) => warn!("storage offer: ingest failed: {e}"),
                }
                send.finish().ok();
            }
            MessageType::STORAGE_RETRACT => {
                // §5.6: retract is a signed statement from the publisher
                // asking honest nodes to stop serving an object. The spec
                // explicitly says we cannot compel; we can ask. Phase 1.5d:
                // we honor the retract by removing the local copy (best-
                // effort — we don't track per-publisher provenance, so this
                // is overbroad if multiple publishers reference the same
                // content-addressed bytes).
                let retract = match StorageRetractPayload::decode(&env.payload) {
                    Ok(r) => r,
                    Err(e) => {
                        warn!("storage retract decode failed: {e}");
                        continue;
                    }
                };
                if services.store.has(&retract.hash).await.unwrap_or(false) {
                    // ObjectStore doesn't expose an explicit `remove`; we use
                    // unpin + leave the entry. Real removal is a Phase-2
                    // storage refinement.
                    let _ = services.store.unpin(&retract.hash).await;
                    debug!("storage retract: unpinned 0x{:02x}…", retract.hash[0]);
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
async fn serve_gossip(session: Session, services: Services) -> Result<()> {
    // Track this connection for fan-out of novel broadcasts.
    {
        let mut active = services.active_gossip.lock().await;
        active.insert(session.peer_side, session.connection.clone());
    }
    let _guard = scopeguard_gossip(services.active_gossip.clone(), session.peer_side);

    // 1. Deliver any pending forwards for this peer.
    let held = services.mailbox.drain(&session.peer_side).await;
    for msg in held {
        let payload = ForwardDeliverPayload {
            envelope: msg.envelope,
            stored_at: msg.stored_at,
        };
        let env = sign_response(
            &services.side,
            &session.peer_side,
            MessageType::FORWARD_DELIVER,
            payload.encode(),
        )?;
        if let Ok((mut send, _recv)) = session.open_and_send(&env).await {
            send.finish().ok();
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
        if !check_freshness_and_replay(&env, &services.replay).await {
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
async fn serve_verse(session: Session, services: Services) -> Result<()> {
    // Snapshot the hosted verse once at session start. No verse → close.
    let host = {
        let g = services.hosted_verse.lock().await;
        match g.as_ref() {
            Some(h) => h.clone(),
            None => {
                debug!("verse intent received but no verse hosted; closing");
                return Ok(());
            }
        }
    };

    // Register this peer's Verse-intent connection for post fanout + key
    // rotation push. RAII guard removes it on exit.
    let peer_side = session.peer_side;
    host.with_mut(|inner| {
        inner
            .active_sessions
            .insert(peer_side, session.connection.clone());
    })
    .await;
    let _guard = VerseSessionGuard {
        host: host.clone(),
        peer_side,
    };

    loop {
        let (mut send, _recv, env) = match session.accept_one().await {
            Ok(triple) => triple,
            Err(Error::Connection(quinn::ConnectionError::ApplicationClosed(_)))
            | Err(Error::Connection(quinn::ConnectionError::ConnectionClosed(_)))
            | Err(Error::Connection(quinn::ConnectionError::LocallyClosed))
            | Err(Error::Connection(quinn::ConnectionError::TimedOut)) => return Ok(()),
            Err(e) => return Err(e),
        };
        if !check_freshness_and_replay(&env, &services.replay).await {
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
                let post = match VersePostPayload::decode(&env.payload) {
                    Ok(p) => p,
                    Err(e) => {
                        warn!("VersePost decode failed: {e}");
                        continue;
                    }
                };
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

                let _ = services
                    .verse_post_tx
                    .send(VersePostReceived {
                        envelope: env,
                        plaintext: plain,
                    })
                    .await;
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
                // Phase 1.5b moderator authority: only the verse's own keypair.
                let verse_pk = host.with(|inner| inner.verse_key.public_bytes()).await;
                if remove.issued_by != verse_pk {
                    debug!("VerseRemove issued_by != verse keypair; rejected");
                    continue;
                }
                if env.from != verse_pk {
                    debug!("VerseRemove envelope from != verse keypair; rejected");
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

/// Fan a novel public broadcast to all other active gossip connections.
async fn fanout_broadcast(services: &Services, env: &Envelope, source_peer: &[u8; 32]) {
    let connections: Vec<([u8; 32], quinn::Connection)> = {
        let active = services.active_gossip.lock().await;
        active
            .iter()
            .filter(|(k, _)| *k != source_peer)
            .map(|(k, c)| (*k, c.clone()))
            .collect()
    };
    for (peer_key, conn) in connections {
        let env = env.clone();
        tokio::spawn(async move {
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

async fn check_freshness_and_replay(env: &Envelope, replay: &Arc<Mutex<ReplayCache>>) -> bool {
    let now = match sidevers_core::envelope::now_unix_seconds() {
        Ok(n) => n,
        Err(_) => return false,
    };
    if env
        .check_freshness(now, sidevers_core::envelope::DEFAULT_MAX_SKEW_SECS)
        .is_err()
    {
        return false;
    }
    let mut nonce_arr = [0u8; NONCE_LEN];
    nonce_arr.copy_from_slice(&env.nonce);
    let mut cache = replay.lock().await;
    !cache.observe(now, &env.from, &nonce_arr)
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
/// gossip relay) is expected to dedup and propagate.
pub async fn publish_broadcast(session: &Session, side: &SideKey, payload: Vec<u8>) -> Result<()> {
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
