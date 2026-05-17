# Sidevers cryptography — audit map

This document is the navigation aid for an independent reviewer assessing the
Sidevers reference node's cryptographic implementation (the Phase-2.5 review
called out in the Launch document, §3.5). It maps each piece of the protocol
spec to the file and function that implements it, names the third-party
primitive used, and flags the deviations and known limitations.

It is the document we hand a reviewer along with the code. Anything in here
should be answerable from the codebase as it stands.

**Status:** Phase 1 + 1.5a/b/c (verse surface) + 1.5d (profile / capability /
retirement) + 1.5e (relationships / lifecycle / jitter) + 1.5f (multi-side
hosting / SQLite persistence / multi-device QR pairing) + 1.5g (live state
delta sync between co-holders) + 1.5h (May 2026 pre-audit hardening) +
**1.5i (May 2026 round-2 fresh-eyes audit: FFI zeroize + catch_unwind +
length cap, SAS wordlist compile-time validation, safe_backup_path
canonicalize + Windows-reserved + NFC + bidi, constant-time hash compare,
IpSybilTracker infra, verse key-rotation idempotent retry)** complete;
**362 tests green** across the workspace + Tauri desktop. Cross-platform
validated for macOS / Linux / Windows / iOS / Android. See
[SECURITY_CHANGELOG.md](SECURITY_CHANGELOG.md) for the audit-driven changes.

---

## 1. Cryptographic primitives in use

| Primitive | Where used | Crate | Version | Why |
|-----------|------------|-------|---------|-----|
| Ed25519 (sign/verify) | identity, envelope sig, contract sig, linkage proof | `ed25519-dalek` | 2.1 | RustCrypto family, audited, widely deployed |
| X25519 (ECDH) | payload encryption (`payload.rs`), session-key handshake (`handshake.rs`), verse content-key sharing | `x25519-dalek` | 2.0 | matches `ed25519-dalek` (curve25519-dalek shared) |
| BLAKE3 | content addressing, envelope to-be-signed digest, transcript MAC | `blake3` | 1.5 | fast, parallel-tree-hash, official |
| HKDF-SHA-512 | side derivation (`keys.rs`), payload key derivation (`payload.rs`), session key derivation (`handshake.rs`), verse-content-key sealing (`verse.rs`) | `hkdf` + `sha2` | 0.12 + 0.10 | RFC 5869 standard, RustCrypto |
| ChaCha20-Poly1305 (AEAD) | payload encryption (DMs), verse-content encryption (`VerseContentKey`) | `chacha20poly1305` | 0.10 | RFC 8439, RustCrypto |
| bech32m (BIP-350) | side / verse address encoding (`address.rs`) | `bech32` | 0.11 | BIP-350 with the right checksum variant |
| CBOR (RFC 8949, deterministic mode §4.2.1) | every on-the-wire payload | hand-rolled in `cbor.rs`; `ciborium` 0.2 only as a sanity-check decoder for round-trip canonicality | n/a | see §3.2 below |
| `getrandom` (OS CSPRNG) | every keypair, every envelope nonce, every AEAD nonce, every verse content key | `getrandom` | 0.2 | refuses to operate if the OS CSPRNG is unavailable (per spec §2.3) |
| `subtle` (constant-time eq) | Confirm-MAC verification (`handshake.rs`) | `subtle` | 2.5 | side-channel-safe comparison |
| `zeroize` (Drop-zeroize) | `MasterKey` / `SideKey` / `VerseContentKey` secret bytes | `zeroize` 1.7 (via `ed25519-dalek`'s `zeroize` feature) | secret material wiped on drop |
| `rustls` (TLS 1.3 transport) | QUIC handshake on `quinn` (channel encryption only; the Sidevers identity is layered above) | `rustls` 0.23 + `ring` | the only role of TLS here is to encrypt the channel and survive network changes — it does NOT carry Sidevers identity |
| `rcgen` (self-signed certs) | per-process throwaway TLS cert for QUIC | `rcgen` 0.13 + `ring` | the Sidevers handshake on top authenticates the actual identity |

**No protocol-level primitive is hand-rolled.** Every cryptographic operation
calls into one of the above libraries.

---

## 2. Spec section → implementation map

### 2.1 Identity (spec §2)

| Spec | Location | Notes |
|------|----------|-------|
| §2.2 primitives (Ed25519 etc.) | `sidevers-core/src/keys.rs` | constants `SECRET_KEY_LEN`, `PUBLIC_KEY_LEN`, `SIGNATURE_LEN` |
| §2.3 master keypair generation; CSPRNG refusal | `MasterKey::generate()` in [keys.rs](crates/sidevers-core/src/keys.rs) | returns `Err(Error::CsprngUnavailable)` if `getrandom` fails |
| §2.4 side derivation (HKDF salt `"sidevers/v1/sides"`, info = label) | `MasterKey::derive_side` | matches spec verbatim |
| §2.5 bech32m addresses with `sv` / `svv` HRPs | `sidevers-core/src/address.rs` | rejects mixed-case + non-bech32m (bech32) checksums explicitly |
| §2.6 unlinkability invariants | structural: side seeds are HKDF-derived; the master is never on the wire | tested by `master_generates_and_derives_independent_sides` |
| §2.7 linkage proofs (dual Ed25519, master not involved) | `sidevers-core/src/linkage.rs` | inline-signed (verifiable standalone); `LinkageProof::from_wire_bytes` re-encodes and asserts byte-identical |
| §2.8 key rotation | `MasterKey::derive_side(label#N)` pattern; on-wire rotation record is not yet emitted (Phase 1.5+) | the underlying derivation supports it; the publishing side hasn't been wired |
| §2.9 loss/recovery | not in protocol scope; key-backup service is a separate product feature | document this in client-side onboarding |

### 2.2 Wire format (spec §3)

| Spec | Location | Notes |
|------|----------|-------|
| §3.1 deterministic CBOR (RFC 8949 §4.2.1) | `sidevers-core/src/cbor.rs` | hand-rolled `CborWriter` emits only shortest-form length encoding; `CborReader` rejects non-shortest-form on parse; `is_sorted_by_key` debug-asserts key order; `ciborium` used only in `assert_canonical` |
| §3.2 envelope shape (8 fields, canonical order) | `sidevers-core/src/envelope.rs` | order pinned in `encode_unsigned` + `to_wire_bytes` |
| §3.2 timestamp skew ±300 s | `Envelope::check_freshness` | enforced via `u64::abs_diff` |
| §3.2 nonce replay window ≥ 600 s | `sidevers-core/src/replay.rs` | sweep-based eviction (NOT touched-on-hit): an attacker who replays a recorded envelope cannot keep the replay-cache entry alive by repeating it |
| §3.3 signing process (BLAKE3 digest, signature over digest) | `Envelope::sign_with` | digest is `BLAKE3(canonical-cbor-of-7-field-map)`; `Envelope::from_wire_bytes` reconstructs and re-verifies; **a re-encode check at the end ensures the input bytes match the canonical re-encode**, catching any non-canonical input that nevertheless decoded |
| §3.4 payload encryption (X25519 ECDH + HKDF + ChaCha20-Poly1305) | `sidevers-core/src/payload.rs` | the spec under-specifies the 12-byte AEAD nonce derivation from the 16-byte envelope nonce; we use the first 12 bytes of the envelope nonce, documented at top of file |
| §3.5 message-type categories (0x00–0x0F drop; 0x70–0xEF return error; 0xF0–0xFF drop) | `MessageType::category()` + serve loops | each `serve_*` handler honors its intent's allowed categories |
| §3.6 64-KiB envelope size limit | `sidevers-net/src/framing.rs` `MAX_ENVELOPE_LEN` | enforced in both directions |
| §3.9 direct-message payloads (kind/body/reply_to/thread) | `sidevers-core/src/messages/direct.rs` | text + reference variants |

### 2.3 Handshake (spec §4)

| Spec | Location | Notes |
|------|----------|-------|
| §4.2 QUIC + TLS 1.3, ALPN `b"sidevers/1"` | `sidevers-net/src/transport.rs` | dual-stack `[::]:port`; self-signed cert per process; 0-RTT disabled (`max_early_data_size = 0`) |
| §4.3 three-message Hello / HelloBack / Confirm | `sidevers-net/src/handshake.rs` `run_initiator` / `run_responder` | ephemeral X25519 keys discarded after `session_key` derivation |
| §4.3.2 session-key derivation | `derive_session_key`: `HKDF-SHA-512(ikm = X25519(my_eph, their_eph), salt = BLAKE3(hello ‖ helloback), info = "sidevers/v1/session", L = 32)` | matches spec verbatim |
| §4.3.3 Confirm = `BLAKE3_keyed_hash(session_key, hello ‖ helloback)` | `transcript_mac` + `subtle::ConstantTimeEq` comparison | constant-time |
| §4.4 single intent per connection | `sidevers-net/src/session.rs::Intent::accepts` | rejected messages return `Error::WrongIntent` |
| §4.5 anonymous handshake variant | `Node::dial_anonymous` returns `(Session, SideKey)` where the side is a fresh ephemeral | tested in `anonymous_dial_uses_ephemeral_side_not_node_primary` |
| §4.6 10-s handshake timeout | `tokio::time::timeout(HANDSHAKE_TIMEOUT, ...)` wrapping both `run_initiator_inner` and `run_responder_inner` | |
| §4.6 per-source rate limit | not yet implemented; documented as a Phase-1.5d hardening item | the TLS layer already imposes a per-source connection rate |
| §4.7 no 0-RTT | enforced in `transport.rs` server + client configs | |

### 2.4 Storage (spec §5)

| Spec | Location | Notes |
|------|----------|-------|
| §5.2 content addressing (BLAKE3) | `sidevers-storage/src/object.rs` | address = `BLAKE3(bytes)` |
| §5.3 References (hash + size + type + hints + deps) | `sidevers-storage/src/reference.rs` | dep traversal has cycle + depth-64 guards |
| §5.4 hash-on-fetch (mandatory) | `verify_hash` in `object.rs`; called from every `get` / `get_range` | proven by `tampered_disk_blob_is_rejected_via_network` conformance test |
| §5.4 0x30–0x32 Get/Have/Miss | `sidevers-net/src/storage_protocol.rs` codecs + `serve_storage` handler | byte-range fetch supported |
| §5.5 0x33–0x34 Offer/Want | full handlers in `serve_storage` + `offer_object` client helper | tested in `storage_offer_want_have_round_trip` and `storage_offer_declined_when_peer_already_has` |
| §5.6 0x35 Retract | `serve_storage` honors by unpinning; `retract_object` client helper signs + sends | limitation: ObjectStore doesn't yet expose a hard `remove` (Phase 2 storage refinement) |

### 2.5 Network (spec §6)

| Spec | Location | Notes |
|------|----------|-------|
| §6.4 PeerAsk / PeerTell | `sidevers-core/src/messages/peer.rs` + `sidevers-net/src/peers.rs` | bounded peer table; eviction by oldest `last_seen` |
| §6.6 Rendezvous / RendezvousAck | `sidevers-core/src/messages/rendezvous.rs` + `serve_gossip` handler | UDP hole-punching itself is a Phase-2 NAT-traversal refinement; the broker protocol exchange works on localhost |
| §6.7 ForwardStore / ForwardDeliver | `sidevers-net/src/forward.rs` + `serve_gossip` | the forwarder sees the outer envelope but the inner is end-to-end encrypted to the recipient — verified by inspection (the inner bytes are opaque `bstr`) |
| §6.8 gossip propagation | `sidevers-net/src/gossip.rs` + `verse_fanout_post` pattern in `serve_gossip` | dedup via `(from, nonce)` cache; fanout to other active gossip peers excluding the source |
| §6.9 web-of-trust filter | not yet implemented; subscription set is the current filter | flagged in CRYPTO §3 below |

### 2.6 Verses (spec §8)

| Spec | Location | Notes |
|------|----------|-------|
| §8.2 verse keypair | the verse's keypair is just another Ed25519 keypair (Sidevers identities and verses share keyspace; only the bech32m HRP differs) | held by `VerseHost::verse_key` |
| §8.3 ContractObject (12 fields, inline-signed) | `sidevers-core/src/verse.rs` | re-encode check on parse. Phase 1.5.B added `moderators: Vec<[u8;32]>` between `signature` and `description` in canonical key order; **wire format is incompatible with pre-1.5.B serializations** — empty list = "verse keypair is sole moderator" (backward-equivalent semantically) |
| §8.4 field kinds | `FieldKind` with well-known constants + `custom:<name>` escape | |
| §8.5 ContractFetch / ContractDeliver / JoinRequest / JoinAccept / JoinDecline (0x50–0x54) | `sidevers-core/src/messages/verse.rs` + `serve_verse` in `node.rs` | tested in `verse_form_join_and_post_round_trip` |
| §8.6 verse content key (32 bytes, ChaCha20-Poly1305) | `VerseContentKey::generate` / `seal` / `open` | 12-byte AEAD nonce drawn from OS CSPRNG per call |
| §8.6.1 content-key distribution at join (X25519 to joining side) | `serve_verse` JOIN_REQUEST branch calls `core_payload::seal` to seal the content key bytes to the joining side's X25519 pubkey | with AAD `"sidevers/v1/verse-key-share"` |
| §8.6.2 key rotation on membership change | `rotate_and_push_verse_key` in `node.rs` | called on VERSE_LEAVE and VERSE_REMOVE |
| §8.6.3 forward secrecy at rotation | tested in `verse_leave_rotates_key_so_old_key_cannot_decrypt`: bob's old key is explicitly used in a decryption attempt against post-rotation ciphertext, and asserted to fail |
| §8.7 amendment + reconsent | `Node::host_amend_verse` pushes `VerseAmend` to active members; `reconsent_to_amendment` is the member-side helper | tested in `verse_live_amend_pushes_new_contract_and_member_reconsents` |
| §8.8 leave + remove + DataDisposition | `VerseLeavePayload` + `VerseRemovePayload` + handlers | DataDisposition is advisory per spec |
| §8.9 moderator authority | Phase 1.5.B: `ContractObject.moderators` on the wire; `is_moderator(side)` returns true for the verse keypair OR any listed side. `VERSE_REMOVE` handler accepts any moderator's signed envelope (sender must equal `issued_by`, no cross-signing). |

### 2.7 Sides — extended surface (spec §7, Phases 1.5d/e/f/g)

| Spec | Location | Notes |
|------|----------|-------|
| §7.3 Profile (signed object, 9-entry CBOR map) | `sidevers-core/src/messages/profile.rs` (`ProfilePayload`) | Ed25519 over BLAKE3(unsigned); re-encode check on parse; capability set as `BTreeSet<String>` for canonical iteration |
| §7.3 Profile fetch/deliver wire types (0x23, 0x24) | `sidevers-core/src/envelope.rs` (constants) + `serve_direct` dispatch in `node.rs` | side-to-side; nonce-bound to the side being queried |
| §7.4 Side relationships (local-only) | `sidevers-net/src/relationships.rs` (`SideRelationship`, `RelationshipTable`) + `sidevers-net/src/side.rs` (write-through to SQLite) | never on the wire (spec §7.4); persisted in `relationships` table |
| §7.4 Per-contact capability override | `Node::capability_allows` 3-tier lookup: relationship → profile → permissive default | empty-set relationship = explicit block |
| §7.5 Multi-device co-holders | `sidevers-core/src/messages/device.rs` (PairingRequest / StateBundle / DeviceRevoke / StateDelta / PairingQr codec) + `sidevers-net/src/node.rs` (`generate_pairing_qr`, `accept_pairing`, `revoke_co_holder`) | state bundle sealed via X25519+ChaCha20-Poly1305 (AAD `"sidevers/v1/device-state-bundle"`) to the new device's pubkey; binding check: outer envelope side == bundle.side AND inner side_seed re-derives bundle.side |
| §7.5 QR-driven pairing nonce | 16-byte CSPRNG nonce recorded in `Side::pending_pairings`; consumed atomically under Mutex in `take_pending_pairing`; 10-minute TTL | replay-safe by construction (single-use entry) |
| §7.6 Per-side independent QUIC endpoints | `Node::add_side` opens a fresh `quinn::Endpoint` per hosted side | honors "no multiplexing across sides" |
| §7.6 Randomized publish jitter | `sidevers-net/src/hygiene.rs` — `apply_publish_jitter` (default 250 ms) | called at the start of `fanout_broadcast` and `publish_broadcast`; disable via `set_jitter_disabled(true)` for deterministic tests |
| §7.7 Capability tokens (6 standard) | `profile::capability::{DIRECT_MESSAGE, STORAGE_HOST, VERSE_MODERATE, GOSSIP_RELAY, DISCOVERABLE, INDEXABLE}` | only DIRECT_MESSAGE is currently enforced at the wire layer; the others round-trip but are advisory until later phases |
| §7.8 Side retirement record | `sidevers-core/src/messages/retirement.rs` (`SideRetirementPayload`, 0x25) | signed by the retiring side; receivers log `WARN` on subsequent signed envelopes (per spec §7.8 "anomalous but accepted") |
| §7.8 Side lifecycle (Created / Active / Dormant / Retired) | `sidevers-net/src/relationships.rs` (`SideLifecycle::derive`) | local-only; derived from `last_local_send_at` |

### 2.8 Multi-device live state sync (spec §7.5+, Phase 1.5g)

| Spec | Location | Notes |
|------|----------|-------|
| State delta wire type (0x29) | `sidevers-core/src/messages/device.rs` (`StateDeltaPayload`, `DeltaOp`) | signed by side keypair (any co-holder can produce); 8 op variants: ProfileUpdated/Cleared, RelationshipUpserted/Removed, RetiredObserved, LifecycleChanged, CoHolderAdded/Removed |
| Auto-push on mutation | `Node::set_local_profile` / `add_relationship` / `remove_relationship` push to all known co-holders via `push_delta_to_co_holders` | fire-and-forget `tokio::spawn` per co-holder; failures log but don't surface to caller |
| Pairing closes the address loop | `Node::accept_pairing` pushes `CoHolderAdded {us, our_listen}` back to existing device after install | enables bidirectional delta flow |
| Last-write-wins conflict resolution | `Side::apply_delta` compares `applied_at` against per-field timestamps | retirement is sticky (cannot un-retire via delta) |
| Self-loop / echo guard | `apply_delta::CoHolderAdded` drops if `device_pubkey == self.address` OR already revoked | prevents infinite-loop / re-add of revoked devices in N≥3 topologies |

### 2.9 SQLite persistence (Phase 1.5f / 1.5g)

| Aspect | Location | Notes |
|--------|----------|-------|
| Per-side state on disk | `sidevers-net/src/side_store.rs` (rusqlite "bundled") | one file at `<data_dir>/sides.db`; tables: `sides`, `profiles`, `retired_sides_seen`, `relationships`, `co_holders`, `revoked_devices`, `co_holder_addrs` |
| Schema versioning | `schema_version` table — currently v2 | v1→v2 migration adds `co_holder_addrs`; **integration-tested** via `v1_database_migrates_to_v2_without_data_loss` |
| At-rest encryption | Not in this phase; the `sides.seed` BLOB column is plaintext | mitigated by OS-level disk encryption + the data_dir directory being mode 0700 (deployer's responsibility); application-level encryption is a Phase 2 hardening |

### 2.10 FFI surface (Phase-3 mobile lite mode)



| Operation | Function | Source |
|-----------|----------|--------|
| Master keygen | `sv_keygen_master` | `crates/sidevers-ffi/src/keys.rs` |
| Side derivation | `sv_derive_side` | same |
| Pubkey extraction | `sv_pubkey_from_seed` | same |
| Address encode / decode | `sv_address_encode` / `sv_address_decode` | `crates/sidevers-ffi/src/address.rs` |
| DM seal + open | `sv_dm_seal_text` / `sv_dm_open_text` | `crates/sidevers-ffi/src/dm.rs` |
| Linkage sign + verify | `sv_linkage_sign` / `sv_linkage_verify` | `crates/sidevers-ffi/src/linkage.rs` |
| Last-error message | `sv_last_error_message` | `crates/sidevers-ffi/src/error.rs` |
| Memory release | `sv_free_buffer` / `sv_free_string` | `crates/sidevers-ffi/src/mem.rs` |

Header: `crates/sidevers-ffi/include/sidevers.h` (auto-generated by `cbindgen`
0.29; committed to the repo so mobile build pipelines don't need cbindgen).

The FFI is the **only** crate in the workspace that allows `unsafe`. Every
library crate has `#![forbid(unsafe_code)]` at the top of its `lib.rs`. The
FFI's unsafety is restricted to the boundary code that converts C raw
pointers / lengths into Rust slices, with `// SAFETY:` comments at every
dereference describing the caller contract.

### 2.11 Public-layer payloads (spec §9, Phase 2 wire scaffold)

| Operation | Source | Notes |
|-----------|--------|-------|
| `HandleResolve` (0x60) | `crates/sidevers-core/src/messages/public.rs` | unsigned request payload |
| `HandleAttest` (0x61) | same | signed: side claims a handle |
| `PagePublish` (0x62) | same | signed: 6-field signed page (slug, mime, content, published_at) |
| `PageFetch` (0x63) | same | unsigned request |
| `PageDeliver` (0x64) | same | wraps a signed `PagePublish` as opaque bstr |
| `Announcement` (0x65) | same | signed: gossip-fanout broadcast |
| `DirectoryEntry` (0x66) | same | composite: aggregates per-side `HandleAttest`s |

The Rust node **ships these codecs but no `serve_public` handler**. The
Phase 2 spec is deliberately Laravel-side (the sidevers.com registry
crate is a separate repo). The codecs let a client sign + dispatch
public-layer envelopes over an existing Direct or Gossip intent
session; the registry's dispatch semantics are out of scope here.

### 2.12 Operational layers (Phase 1 H1–H4, B1)

| Concern | Source | Notes |
|---------|--------|-------|
| Per-source-IP handshake rate limit (§4.6) | `crates/sidevers-net/src/handshake_limit.rs` | token bucket per `IpAddr`; checked before responder handshake runs |
| TLS cert pinning + permissive default | `crates/sidevers-net/src/cert.rs` | `CertPinTable` + `PinnedOrAccept` verifier. **Opt-in:** empty pin set = current "accept any well-formed cert" behavior; once pinned, BLAKE3 fingerprint must match. Default-permissive because Sidevers authenticates at the protocol layer (Hello/Confirm Ed25519), not TLS. |
| QUIC connection pool | `crates/sidevers-net/src/connection_pool.rs` | keyed on `(peer_addr, source_side)` per §7.6 — two sides MUST NOT multiplex |
| NAT hole-punching | `crates/sidevers-net/src/hole_punch.rs` | symmetric-retry double-connect; cone NATs only; symmetric-NAT prediction explicitly deferred |
| Prometheus `/metrics` endpoint | `crates/sidevers-net/src/metrics.rs` | 14 counters; `serve_on_local(port)` binds 127.0.0.1 only; `serve_on(addr)` documented as "behind an external firewall" |
| Gossip fanout WoT filter | `crates/sidevers-net/src/gossip_policy.rs` | configurable `Open` / `ExcludeRefused` / `RelationshipsOnly`; default `Open` |
| Storage publisher provenance | `crates/sidevers-net/src/provenance.rs` | `STORAGE_RETRACT` only honored from sides recorded as publishers; unpin only when last publisher retracts |
| Replay cache memory bound | `crates/sidevers-core/src/replay.rs` | `DEFAULT_MAX_ENTRIES = 16_384`; oldest-first eviction with optional journal write-through |
| Replay cache persistence | `crates/sidevers-net/src/replay_journal.rs` | SQLite journal; WAL + synchronous=NORMAL; window survives restart |
| LRU storage eviction | `crates/sidevers-storage/src/object.rs` `evict_to_budget` + `objects_evict` index in `db.rs` | unpinned objects only; pinned never evict |
| Object chunking | `crates/sidevers-storage/src/chunking.rs` | 256 KiB chunks + content-addressed manifest; `out.len() == declared_total` sanity check |
| Inbox persistence | `crates/sidevers-net/src/inbox_store.rs` | SQLite; WAL pragmas; per-recipient list ordered by received_at |
| Clock-skew graceful fallback | `crates/sidevers-core/src/envelope.rs` `SOFT_MAX_SKEW_SECS = 900` | tiered: ≤300s silent, 300–900s warn-and-accept, >900s reject |
| Filesystem permissions | `crates/sidevers-net/src/fs_perms.rs` | every SQLite file chmod 0o600, data dirs chmod 0o700 on Unix |
| Feature deprecation pipeline | `crates/sidevers-core/src/features.rs` | `FeatureState::{Active, Deprecated, Frozen}` registry; `phase1_baseline()` lists every wire feature |

---

## 3. Threat model — what's defended, what isn't

### What the protocol defends against

* **A passive network observer.** Cannot read message contents (every
  payload is end-to-end encrypted per §3.4 or verse-key encrypted per
  §8.6). Cannot link two sides of the same person (§2.6, §7.6). Cannot
  enumerate the network (no global broadcast / no global view).
* **An active network attacker.** Cannot impersonate either party
  (Ed25519 signatures on every envelope, X25519-rooted session key on
  every handshake). Cannot decrypt traffic in transit (TLS 1.3 +
  per-message AEAD). Cannot replay old envelopes (§3.2 nonce cache +
  freshness window). Cannot downgrade the protocol version (the chosen
  version is in the signed handshake transcript). Can deny service but
  not read or forge.
* **A malicious peer.** Cannot read direct messages addressed to others
  (X25519 ECDH bounds decryption to the recipient). Cannot publish on
  behalf of others (envelope signatures verify against `from`). Cannot
  forge verse memberships (membership tokens carry the verse's signature;
  the verse's keypair is the moderator). Cannot tamper with stored
  content (BLAKE3 content-addressing; hash-on-fetch).
* **A compromised storage node.** Cannot read encrypted objects
  (ciphertext at rest). Cannot tamper without detection (BLAKE3
  re-verification on every read; the conformance suite proves this with
  a tampered-blob-on-disk test).
* **A compromised registry node.** Cannot forge handle ownership /
  quietly substitute page content / read private content / impersonate a
  side (none of these touch the private network; the registry's role is
  the public layer only, which is Phase 2).

### What's explicitly out of scope

* **A global passive adversary watching all traffic everywhere.**
  Sidevers is not Tor. Users with this threat model should run Sidevers
  over Tor or a similar overlay.
* **An attacker who roots the user's device.** They have the keys; no
  protocol layer can defend against that.
* **Coerced disclosure by the user.** A protocol cannot defend against a
  user being threatened, deceived, or compelled into revealing keys or
  content.
* **Side-channel attacks on the cryptographic primitives.** Those are
  the cryptographic libraries' problem (the `subtle` crate's
  constant-time-eq guards the one comparison where it matters — Confirm
  MAC verification).
* **Quantum adversaries.** Ed25519 and X25519 are not post-quantum. The
  spec explicitly defers post-quantum to a v2 protocol revision; the
  versioning machinery in §10.3 supports clean migration.

### Honest tradeoffs documented in the spec we still honor

* **Self-custody versus recoverability** — a user who loses all their
  devices and never opted into key backup has lost their identity. The
  protocol gives control; the product can offer (separately) a backup
  service that trades some control back for safety.
* **Unlinkability versus convenience** — two sides on one device require
  independent QUIC connections per spec §7.6; we enforce this in the
  connection pool key.

---

## 4. Known limitations and deviations

These are documented honestly. They're either deferred to a later phase
or genuine gaps to flag.

1. **Spec gap: AEAD nonce derivation in §3.4 is under-specified.** The
   spec gives the 32-byte key (via HKDF) but doesn't explicitly say how
   the 12-byte ChaCha20-Poly1305 nonce is derived from the 16-byte
   envelope nonce. We use the first 12 bytes of the envelope nonce.
   This gives unique (key, AEAD-nonce) pairs per envelope. **Reviewers
   should confirm this is acceptable** and the spec should be amended to
   match before v1.0 final. See `payload.rs` top comment.

2. ~~Per-source handshake rate-limiting is not yet implemented.~~
   **CLOSED Phase 1.D** — `crates/sidevers-net/src/handshake_limit.rs`
   adds a per-source-IP token bucket consulted before the responder
   handshake runs.

3. **Web-of-trust gossip filter is opt-in.** Spec §6.9. The
   `GossipPolicy::ExcludeRefused` and `RelationshipsOnly` modes in
   `gossip_policy.rs` are wired but `Open` remains the default so
   existing dispatch tests pass. The reachable-by-follow-graph
   semantics depend on follow-graph protocol additions that are still
   Phase-2 work; the operator-tunable infrastructure is present.

4. ~~Storage `Retract` is overbroad.~~ **CLOSED Phase 1.C3** —
   `provenance.rs` tracks the set of publishers per content-addressed
   hash; `STORAGE_RETRACT` only fires when the sender is recorded as a
   publisher, and unpin only when the last publisher retracts.

5. ~~Multiple verse moderators aren't on the wire.~~ **CLOSED Phase
   1.5.B** — `ContractObject.moderators: Vec<[u8; 32]>` is now part of
   the canonical 12-key signed form; `VERSE_REMOVE` accepts any
   moderator's signed envelope. See §8.3 row above for the wire-format
   note: **the change is incompatible with pre-1.5.B serializations.**

6. **Verse-post persistence is in-memory only.** Phase 1.5.D added
   `crates/sidevers-net/src/verse_post_store.rs` which retains sealed
   posts so `DataDisposition::Retract` can act on them, but the store
   doesn't survive restart. A SQLite-backed `VersePostStore` is
   straightforward (mirror the `replay_journal.rs` pattern) but kept
   for Phase 2.

7. **The DataDisposition `transfer` option is wire-correct but inert.**
   Spec §8.8 says the disposition is advisory; we honor `retract`
   (drops the author's stored posts via `retract_by_author` Phase 1.5.D)
   but `transfer` (export-with-data) is a UX-driven client feature,
   not a protocol mechanism.

8. **Session resumption (0-RTT) is deliberately not implemented**, per
   spec §4.7. v1's freshness guarantees depend on the full handshake
   each time.

9. ~~NAT hole-punching is not implemented.~~ **CLOSED Phase 1.B1** —
   `crates/sidevers-net/src/hole_punch.rs` ships a symmetric-retry
   double-connect that handles cone NATs. Symmetric-NAT prediction
   (which needs STUN-style port prediction) is still deferred.

10. **iOS/Android runtime testing is not in CI.** Cross-compile checks
    (compile-only) are in CI for all five mobile targets. Runtime tests
    on real devices is Phase-3 mobile-client work.

11. **Multi-device live state sync uses transport-only encryption.**
    Phase 1.5g's `STATE_DELTA` envelopes (0x29) carry profile,
    relationships, retired-sides observations, and lifecycle deltas
    between co-holders. The OUTER envelope is signed by the side
    keypair (Ed25519), but the PAYLOAD is **not** end-to-end sealed via
    X25519+ChaCha20 — only the QUIC transport (TLS 1.3 with `rustls` +
    `ring`) protects it on the wire. A relay or path observer that
    compromises the TLS material could read deltas in flight. Co-holders
    are *equally privileged* per spec §7.5 (they share the side keypair),
    so end-to-end sealing the delta would only protect against the
    transport-layer adversary — a real concern but bounded. Adding
    per-device attestation chains + delta sealing is Phase 1.5h+.

12. **Side seed stored in cleartext in SQLite.** The `sides.seed` column
    in `<data_dir>/sides.db` holds the 32-byte side secret in the clear.
    Loss of the DB file = loss of all side identities + ability to
    impersonate any hosted side. Mitigations:
    - **Phase 1.H1 audit-pass added `fs_perms.rs`** which chmods the
      file to 0o600 + the data dir to 0o700 on every store open (Unix
      only; no-op on Windows). Other local users on the same Unix box
      can no longer read the seed.
    - **Phase 1.5h (May 2026) added `sidevers_core::keystore`**, a
      passphrase-sealed seed format (Argon2id KDF +
      ChaCha20-Poly1305 AEAD with format params bound in AAD). The
      Tauri client's "back up seed" flow now writes only the sealed
      form; `sidevers-node` accepts both legacy plaintext seeds (with
      a stderr warning) and sealed seeds (passphrase via
      `SIDEVERS_SEED_PASSPHRASE`). See [SECURITY_CHANGELOG.md](SECURITY_CHANGELOG.md)
      P1.1 + P1.2.
    - **Still cleartext at rest:** the *running* `<data_dir>/sides.db`
      itself is not yet encrypted. Encrypting the SQLite store (via
      SQLCipher or app-level page encryption keyed from the master
      seed) is the next step — see SECURITY_CHANGELOG.md "Deferred."
    - The deployer is still expected to keep the data_dir under
      OS-level disk encryption (FileVault on macOS, LUKS on Linux,
      BitLocker on Windows, iOS/Android app-private-data sandbox on
      mobile).

13. **Multi-device network-level revocation is local-only.** When a
    co-holder publishes `DeviceRevoke` (0x28), other co-holders mark the
    revoked device locally and refuse to re-add it via state-delta sync.
    But because the side keypair is shared across all co-holders (per
    spec §7.5), peers receiving an envelope signed by the side keypair
    have no way to distinguish a revoked device's signature from any
    other co-holder's. Proper network-level revocation requires per-
    device attestation chains (each device has its own keypair, side
    delegates with signed records). Phase 1.5h+.

14. **TLS cert pinning is opt-in / `permissive` by default.** Phase 1.H2
    added the pinning machinery (`cert.rs`) but the default verifier
    is `PinnedOrAccept` with an empty pin set — i.e. "accept any
    well-formed cert." This preserves the pre-1.H2 behavior the
    Sidevers handshake at the protocol layer (Hello/Confirm Ed25519)
    relies on for identity. Operators who want defense-in-depth pin
    expected peer cert fingerprints via `Node::cert_pins().pin(addr,
    hash)`. The pin verifier is then enforced for those addresses.

15. **Metrics endpoint has no auth.** Phase 1.H3 added a Prometheus
    `/metrics` endpoint that exposes counter values without any
    authentication or TLS. Counter values reveal operationally-sensitive
    information — peer pubkeys that have spoken to this node + at what
    rate. Operators MUST bind it to a private interface; the
    `Metrics::serve_on_local(port)` convenience binds to `127.0.0.1`
    only. The general `serve_on(addr)` is documented with a Security
    block warning against `0.0.0.0` binds.

16. **Tauri client CSP includes `style-src 'self' 'unsafe-inline'`.**
    Needed because the `qrcode` crate emits SVG with inline `style`
    attributes. `'unsafe-inline'` is a broad CSS-injection permission
    that's currently safe because we don't render attacker-supplied
    SVG, but it should be dropped once the QR rendering moves to
    canvas / `<img src="data:…">` (Phase 2 client polish). All other
    CSP directives are tight: `default-src 'self'`, `object-src
    'none'`, `frame-src 'none'`, `base-uri 'self'`, `form-action
    'none'`.

17. **The Phase 2 Public-layer payloads have no `serve_public` handler.**
    `crates/sidevers-core/src/messages/public.rs` ships codecs for all
    seven Public-layer message types (§2.11) but the node doesn't have
    a Public-intent server loop yet. By design — Phase 2 dispatch is
    a sidevers.com Laravel registry concern, and committing prematurely
    to handler semantics here would couple the reference node to a
    spec that hasn't fully landed. The codecs are ready when needed.

---

## 5. How to verify

### Run the full test suite

```
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

All 142+ tests must pass on Linux, macOS, and Windows. Storage hash-on-
fetch, replay rejection, forward secrecy at verse-key rotation,
signature-flip rejection on every signed envelope, and the
multi-process gossip-through-relay scenario are all covered.

### Cross-compile for mobile targets

```
rustup target add aarch64-apple-ios aarch64-apple-ios-sim aarch64-linux-android x86_64-linux-android
# iOS (requires macOS + Xcode CLI tools):
cargo check --target aarch64-apple-ios -p sidevers-core -p sidevers-storage -p sidevers-net -p sidevers-conformance -p sidevers-ffi
# Android (requires NDK):
cargo check --target aarch64-linux-android -p sidevers-core -p sidevers-storage -p sidevers-net -p sidevers-conformance -p sidevers-ffi
```

CI runs this matrix on every PR.

### Run the fuzz harness (requires nightly Rust + cargo-fuzz)

```
rustup install nightly
cargo install cargo-fuzz
cd fuzz
cargo +nightly fuzz run envelope_decode
cargo +nightly fuzz run cbor_decode
cargo +nightly fuzz run direct_message_decode
```

Each target hammers a decoder with arbitrary bytes; any panic indicates
a protocol-level DoS vulnerability worth investigating.

### Verify the FFI surface from C

```
cargo build --release -p sidevers-ffi
# produces target/release/libsidevers.{a,dylib,so}
# header at: crates/sidevers-ffi/include/sidevers.h
```

The 9 integration tests in `crates/sidevers-ffi/tests/roundtrip.rs`
exercise the C ABI exactly as a Swift/Kotlin client would.

---

## 6. Reviewer-suggested reading order

Approximately one hour to gain confidence in the protocol code; longer
for deep adversarial reasoning.

1. **Start here:** the spec PDF (`Downloads/sidevers-complete_3.pdf`)
   §§2–3 — the identity model and the envelope. The protocol's whole
   security story sits on these 12 pages.
2. **`crates/sidevers-core/src/cbor.rs`** — deterministic CBOR. Every
   signed object's integrity depends on this being right. The
   shortest-form length encoding and the map-key-order assertion are the
   bits to scrutinize.
3. **`crates/sidevers-core/src/envelope.rs`** — the envelope sign /
   verify flow, especially `from_wire_bytes`. The re-encode-and-compare
   check at the end is the belt-and-braces defense against non-canonical
   inputs that nevertheless decoded.
4. **`crates/sidevers-core/src/keys.rs`** + **`payload.rs`** — key
   derivation and X25519/ChaCha20-Poly1305 sealing. Note the §3.4 spec
   gap above.
5. **`crates/sidevers-net/src/handshake.rs`** — the three-message
   handshake state machine. Transcript binding (§4.3.2) and Confirm-MAC
   (§4.3.3) are the points where the channel attaches to identity.
6. **`crates/sidevers-net/src/node.rs`** — `serve_verse`,
   `rotate_and_push_verse_key`, and `verse_fanout_post`. Verse-key
   rotation on membership change is the most subtle piece in Phase 1.5.
7. **`crates/sidevers-conformance/src/harness.rs`** — every conformance
   scenario is documented with the spec section it exercises.

If anything in here doesn't match the code, the code is wrong (this
document tracks the implementation as it stands). Please flag.
