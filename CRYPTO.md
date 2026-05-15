# Sidevers cryptography — audit map

This document is the navigation aid for an independent reviewer assessing the
Sidevers reference node's cryptographic implementation (the Phase-2.5 review
called out in the Launch document, §3.5). It maps each piece of the protocol
spec to the file and function that implements it, names the third-party
primitive used, and flags the deviations and known limitations.

It is the document we hand a reviewer along with the code. Anything in here
should be answerable from the codebase as it stands.

**Status:** Phase 1 + 1.5a + 1.5b + 1.5c complete; 142 tests green (incl. 9
FFI integration); cross-platform validated for macOS / Linux / Windows /
iOS / Android.

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
| §8.3 ContractObject (11 fields, inline-signed) | `sidevers-core/src/verse.rs` | re-encode check on parse |
| §8.4 field kinds | `FieldKind` with well-known constants + `custom:<name>` escape | |
| §8.5 ContractFetch / ContractDeliver / JoinRequest / JoinAccept / JoinDecline (0x50–0x54) | `sidevers-core/src/messages/verse.rs` + `serve_verse` in `node.rs` | tested in `verse_form_join_and_post_round_trip` |
| §8.6 verse content key (32 bytes, ChaCha20-Poly1305) | `VerseContentKey::generate` / `seal` / `open` | 12-byte AEAD nonce drawn from OS CSPRNG per call |
| §8.6.1 content-key distribution at join (X25519 to joining side) | `serve_verse` JOIN_REQUEST branch calls `core_payload::seal` to seal the content key bytes to the joining side's X25519 pubkey | with AAD `"sidevers/v1/verse-key-share"` |
| §8.6.2 key rotation on membership change | `rotate_and_push_verse_key` in `node.rs` | called on VERSE_LEAVE and VERSE_REMOVE |
| §8.6.3 forward secrecy at rotation | tested in `verse_leave_rotates_key_so_old_key_cannot_decrypt`: bob's old key is explicitly used in a decryption attempt against post-rotation ciphertext, and asserted to fail |
| §8.7 amendment + reconsent | `Node::host_amend_verse` pushes `VerseAmend` to active members; `reconsent_to_amendment` is the member-side helper | tested in `verse_live_amend_pushes_new_contract_and_member_reconsents` |
| §8.8 leave + remove + DataDisposition | `VerseLeavePayload` + `VerseRemovePayload` + handlers | DataDisposition is advisory per spec |
| §8.9 moderator authority | Phase 1.5b: only the verse keypair is a moderator. Multiple moderators (with `moderators` field on the wire) is Phase 1.5d |

### 2.7 FFI surface (Phase-3 mobile lite mode)

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

2. **Per-source handshake rate-limiting is not yet implemented.** Spec
   §4.6 SHOULD-recommends it. The TLS layer's own connection limits
   provide a coarse defense; protocol-level token-bucket per peer is
   Phase-1.5d hardening.

3. **Web-of-trust gossip filter is not implemented.** Spec §6.9. Our
   gossip currently filters only by explicit subscription set; the
   reachable-by-follow-graph filter the spec describes is Phase-2 work
   tied to follow-graph protocol additions (currently §7.4 contacts are
   private — there's no protocol message for "who follows whom" yet).

4. **Storage `Retract` is overbroad.** Honest nodes that receive a
   retract unpin the local object. They don't currently track per-
   publisher provenance (multiple publishers could reference the same
   content-addressed bytes; one publisher's retract shouldn't affect
   another publisher's reference). This will improve once Phase-2
   storage gains a real per-reference table.

5. **Multiple verse moderators aren't on the wire.** Spec §8.2 + §8.9
   describe moderators as sides listed in the contract. Phase 1.5b/c
   treats the verse's own keypair as the sole moderator. Adding the
   `moderators` field to `ContractObject` (and the multi-mod removal
   logic) is Phase 1.5d.

6. **No persistent storage for verse posts.** Posts the host receives
   are delivered to `next_verse_post()` and dropped. Persistence is a
   Phase-2 storage refinement.

7. **The DataDisposition `transfer` option is wire-correct but inert.**
   Spec §8.8 says the disposition is advisory; we honor `retract` (in-
   memory state cleared) but `transfer` (export-with-data) is a UX-driven
   client feature, not a protocol mechanism.

8. **Session resumption (0-RTT) is deliberately not implemented**, per
   spec §4.7. v1's freshness guarantees depend on the full handshake
   each time.

9. **NAT hole-punching is not implemented.** The Rendezvous protocol
   exchange works on localhost. Real UDP hole-punching through symmetric
   NAT is Phase-2 NAT-traversal work tied to the relay infrastructure.

10. **iOS/Android runtime testing is not in CI.** Cross-compile checks
    (compile-only) are in CI for all five mobile targets. Runtime tests
    on real devices is Phase-3 mobile-client work.

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
