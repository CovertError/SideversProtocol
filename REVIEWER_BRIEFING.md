# Reviewer briefing — Sidevers Phase 1 + 1.5 reference node

If you're an external cryptography reviewer who just got handed this
repo: read this document first. It's the orientation pass before
`CRYPTO.md` (the implementation map) and the spec PDF.

## What you've been asked to do

Sidevers's launch plan calls for an independent cryptography review
(Phase 2.5) of the Phase 1 + 1.5 reference implementation. Your job is
to validate that the **cryptographic choices implemented here** match
the spec and don't introduce vulnerabilities; you're **not** being
asked to evaluate the spec's design itself.

Specifically, please confirm or refute:

1. The implementation correctly uses Ed25519 (envelope + record
   signing), X25519 (handshake + payload sealing), BLAKE3 (content
   addressing + transcript hashing + signature input), ChaCha20-Poly1305
   (AEAD for E2E payloads + verse content), HKDF-SHA-512 (session-key
   derivation from the ECDH shared secret).
2. The signed-envelope verification path (`Envelope::from_wire_bytes`)
   genuinely refuses tampered inputs, including non-canonical CBOR
   that nonetheless decodes successfully.
3. The handshake state machine (Hello → HelloBack → Confirm)
   transcript-binds the negotiated session key to the identities and
   to the chosen intent + protocol version.
4. The replay-cache + freshness-window combination genuinely defeats
   the obvious replay strategies (including hammering an old envelope
   to extend its cache lifetime — we tested that explicitly).
5. The verse content-key rotation on membership change (§8.6.2)
   genuinely gives forward secrecy: a member who left in v1 cannot
   decrypt posts encrypted under v2.
6. Multi-moderator dispatch (Phase 1.5.B) correctly requires the
   envelope's sender to be a side listed in `contract.moderators`
   OR equal to the verse's own keypair — no looser, no tighter.
7. The CLI seed-file handling, SQLite-backed stores, and Tauri
   client's persistent inbox don't accidentally leak raw key
   material on multi-user systems (file permissions are 0o600;
   the new `fs_perms.rs` chmod helper is called from every store
   open).

If anything here doesn't match the code, **the code is wrong** —
this document and CRYPTO.md track the implementation as it stands.
Please flag.

## Threat model — what's defended, what isn't

**Defended:**

- **Passive network observers** — cannot read message contents
  (E2E AEAD), cannot link two sides of the same person (independent
  endpoints per spec §7.6), cannot enumerate the network (no global
  view / broadcast).
- **Active MITM attackers** — cannot impersonate, decrypt in
  transit, replay old envelopes (300s freshness + persistent replay
  cache that survives restart, Phase 1.E), or downgrade the
  protocol version (transcript-bound to the signed handshake).
  Cannot extend a replay's cache lifetime by hammering it (tested).
- **Malicious peers** — cannot read DMs addressed to others
  (X25519 ECDH bounds decryption to recipient), cannot publish on
  behalf of others (Ed25519 envelope signatures), cannot forge
  verse memberships (membership tokens signed by the verse
  keypair), cannot retract someone else's storage object (Phase
  1.C3 publisher-provenance — only sides recorded as publishers
  can retract, last publisher to retract triggers unpin).
- **Misbehaving peers** at the rate level — per-peer reputation
  + token bucket (Phase 1.A1/A2), per-source-IP handshake limit
  (Phase 1.D), pre-handshake DoS mitigations apply before any
  expensive crypto.
- **Compromised storage nodes** — cannot tamper without detection
  (BLAKE3 content addressing, hash-on-fetch §5.4 enforced by
  `ObjectStore::get` on every read; conformance test
  `tampered_disk_blob_is_rejected` proves it).
- **Other local users on shared Unix boxes** — Phase 1.H1 audit-pass
  chmod 0o600 on every SQLite file (sides.db with raw seeds,
  inbox plaintext, replay journal) and 0o700 on the data dir.

**Explicitly NOT defended:**

- **A global passive adversary watching all traffic everywhere.**
  Sidevers is not Tor. Users with that threat model should run
  Sidevers over Tor or an equivalent overlay.
- **A compromised local root.** They have the keys; no protocol
  layer can defend against that.
- **Side-channel attacks on the underlying crypto primitives.**
  Those are the cryptographic libraries' (`ed25519-dalek`,
  `x25519-dalek`, `chacha20poly1305`, `blake3`, `ring`) problem.
  The `subtle` crate's constant-time-eq guards the one comparison
  where it matters (Confirm-MAC verification).
- **Quantum adversaries.** Ed25519 + X25519 are not post-quantum.
  Spec §10.3 defines a migration path for v2.
- **Traffic-analysis resistance.** Connection metadata (source IP,
  packet timing) is observable. Application-layer publish-jitter
  (`hygiene.rs::apply_publish_jitter`) blunts the most obvious
  fingerprinting but is not a defense against a determined
  observer.
- **Compromised TLS material.** Phase 1.5g `STATE_DELTA` envelopes
  between co-holders are signed by the side keypair (Ed25519) but
  the payload is NOT end-to-end sealed via X25519+ChaCha20 — only
  the QUIC TLS protects it on the wire. Co-holders are
  equally-privileged per §7.5 so end-to-end sealing the delta would
  only defend against a transport-layer attacker. Real but bounded
  concern.

## 30-minute walkthrough — what to read first

If you have 30 minutes, this is the order that gives the most
confidence per minute spent:

1. **Spec PDF, §§2–3** (12 pages). Identity + envelope. The
   protocol's whole security story sits here.
2. **`crates/sidevers-core/src/cbor.rs`**. The deterministic CBOR
   reader/writer + the canonical key-order assertion. Every
   signed object's integrity depends on this being right.
3. **`crates/sidevers-core/src/envelope.rs`**, specifically
   `from_wire_bytes`. The re-encode-and-compare check at the end
   is the belt-and-braces defense against non-canonical inputs
   that nevertheless decoded.
4. **`crates/sidevers-core/src/payload.rs`**. X25519 ECDH + the
   ChaCha20-Poly1305 sealing path. Note the §3.4 spec gap called
   out at the top — we use the first 12 bytes of the envelope
   nonce as the AEAD nonce; the spec is silent on derivation. We
   want your reading on whether this is acceptable.
5. **`crates/sidevers-net/src/handshake.rs`**. Three-message
   handshake. Transcript binding (§4.3.2) and Confirm-MAC
   verification (§4.3.3) are where the channel attaches to identity.
6. **`crates/sidevers-net/src/node.rs`**, specifically:
   - `VERSE_REMOVE` handler (~line 2392+) — Phase 1.5.B
     multi-moderator authority check
   - `LINKAGE_PUBLISH` handler (~line 1378+) — Phase 1.G1
     publication wire path, sender must be linked
   - `serve_verse` (~line 2095+) — Phase 1.5.E multi-verse
     routing, contract_hash index, key rotation on membership
     change
7. **`crates/sidevers-conformance/src/harness.rs`**. Every
   conformance scenario is documented with the spec section it
   exercises; this is the "we believe these invariants hold"
   ground truth. Scenarios of particular interest:
   - `verse_leave_rotates_key_so_old_key_cannot_decrypt`
     (forward secrecy on membership change)
   - `invariant_no_anonymous_routing_envelope_signature_must_match_from`
   - `invariant_no_global_broadcast_third_party_not_in_session_never_sees_it`
   - `linkage_proof_rejected_when_sender_is_neither_linked_side`
   - `storage_retract_ignored_when_sender_never_published_the_object`

After 30 minutes you'll have a working mental model. The remaining
hours go to spec → code cross-checks driven by the `CRYPTO.md`
"Spec section → implementation map" table.

## Known limitations the reviewer should weigh

These are documented honestly in `CRYPTO.md §4` (numbered list).
The ones that matter most for your review:

- **#1 §3.4 AEAD nonce derivation under-specified.** We pick the
  first 12 bytes of the 16-byte envelope nonce. The envelope nonce
  is per-message CSPRNG-drawn, so (key, AEAD-nonce) pairs are
  unique with overwhelming probability. We want your sign-off on
  this OR a recommended alternative for the spec to adopt before
  v1.0 final.
- **#11 Co-holder STATE_DELTA is transport-encrypted only.** Phase
  1.5g; the payload is signed by the side keypair but not E2E
  sealed. We argue co-holders are equally-privileged per §7.5;
  please tell us if this argument holds.
- **#12 Side seeds at rest are unencrypted SQLite BLOBs.** Phase
  1.H1 audit-pass added owner-only file permissions (0o600 file,
  0o700 dir on Unix); on Windows the OS default ACLs apply.
  Application-level encryption via OS-keychain-derived KEK is
  deferred to Phase 2.
- **#14 TLS pinning is opt-in / permissive by default.** Phase
  1.H2 added the pinning machinery (`cert.rs`); the default
  verifier accepts any cert because Sidevers authenticates at
  the protocol layer (Ed25519 Hello/Confirm). Operators who want
  defense-in-depth pin via `Node::cert_pins().pin(addr, hash)`.
- **#15 Metrics endpoint has no auth.** Counter values reveal peer
  pubkeys + rates. `Metrics::serve_on_local(port)` binds 127.0.0.1
  only; `serve_on(addr)` is documented as "behind an external
  firewall."

## Scope boundaries

- **In scope:** Phase 1 (network protocol, handshake, envelope,
  replay, storage, discovery), Phase 1.5 (verses, multi-side,
  multi-device pairing, multi-moderator), Phase 1 audit-pass
  hardening (file perms, SQLite WAL, LRU index, chunking length
  check, metrics localhost).
- **Out of scope:** Phase 2 (the sidevers.com Laravel registry —
  separate repo; the Public-layer wire codecs we ship in
  `messages/public.rs` are just so the Rust node can sign and
  dispatch envelopes when the registry comes online). Phase 3.F
  Flutter mobile client (not built yet). macOS/Windows code
  signing (operator responsibility).
- **Spec design (NOT in scope for your review):** whether
  Ed25519+X25519+BLAKE3+ChaCha20-Poly1305 are the right primitive
  choices; whether the verse content-key distribution model is
  right; whether the moderator authority model is the right
  governance shape. Those are the original protocol designer's
  decisions; we're asking you whether **the implementation
  faithfully realizes them**.

## Test vectors

The conformance crate ships byte-stable fixtures any conforming
implementation should reproduce:

- **`crates/sidevers-conformance/src/fixtures.rs`** — fixture
  helpers + `fixture_envelope_byte_stable` /
  `fixture_linkage_proof_byte_stable` / etc. tests that assert
  exact bytes for known inputs. If your independent implementation
  differs on any of these, that's a divergence to flag.

Each fixture's expected byte sequence is committed to the repo so
diff-based regression detection works (a primitive-library upgrade
that changes a CSPRNG sequence would silently break one of these).

## Bundle handoff

Run `scripts/audit-bundle.sh` from the repo root to produce a
self-contained tarball: code + this briefing + CRYPTO.md + the
test suite output + the clippy output. One file you can hand to
the reviewer.

## Questions, redirects, push-back

If a finding turns up that's already documented as a known
limitation, please rate it anyway — your independent judgment on
"is this an acceptable tradeoff" is what we're paying for. If a
finding is genuinely new and severe, please flag at
omar@cyberagora.sa with subject `Sidevers Phase 2.5 — <severity>:
<one-line>`.
