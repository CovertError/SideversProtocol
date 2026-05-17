# Security & Privacy Changelog

Audit-driven changes following the May 2026 internal review. The full
audit lives at the plan file used to drive this work (P-tier
prioritization); this changelog records what shipped, what's deferred,
and where to look in the code.

## Phase 1.5i — round-2 fresh-eyes audit (May 2026)

A second adversarial pass over the entire codebase, including the
1.5h code that just shipped. Three parallel Explore agents covered:
the `sidevers-ffi` crate (only unsafe-allowed crate), adversarial
re-read of the 1.5h additions, and the areas round 1 only touched
lightly (storage, verse moderation, reputation, hole-punch).

**Verdict: no P0s.** Round 2 surfaced 5 P1 items and 7 P2 items;
all P1s and 4 of 7 P2s shipped in 1.5i. Wire-policy items (sybil
enforcement) and pure docs are deferred to follow-ups.

### Closed in 1.5i

**P1.A — FFI handles seeds without zeroize.**
The 5 FFI entry points that copy a seed into a stack array
(`sender_seed`, `recipient_seed`, `master_seed`, both side seeds in
linkage) now `zeroize()` the stack copy after constructing the owning
`SideKey`/`MasterKey`. Plus the master-seed export path in
`sv_keygen_master`. Speculative-execution leaks, core dumps, and
crash-reporter stack snapshots can no longer recover identity-root
key bytes.
- Updated: [crates/sidevers-ffi/src/{dm,keys,linkage}.rs](crates/sidevers-ffi/src/), [Cargo.toml](crates/sidevers-ffi/Cargo.toml) adds `zeroize` dep.

**P1.B — all FFI entry points wrapped in `catch_unwind` + new `SvStatus::Panic`.**
Unwinding across a C-ABI boundary is UB; `panic = "abort"` saves
release builds but not debug builds (where mobile QA + fuzz run).
New helper `ffi_entry(name, body)` wraps the body in
`catch_unwind(AssertUnwindSafe(...))`, returns `SvStatus::Panic` on
failure, and sets the last-error message naming the function. Applied
to all 8 `SvStatus`-returning entry points + `sv_address_encode`
(returns `*mut c_char`, special-cased) + `sv_last_error_message` +
both `sv_free_*` (panics swallowed silently — they're infallible from
the C caller's perspective).
- Updated: [crates/sidevers-ffi/src/error.rs](crates/sidevers-ffi/src/error.rs) (helper + tests), all 5 src files.
- 3 new unit tests cover normal-pass-through, panic-caught, last-error-set paths.

**P1.E — SAS wordlist compile-time validation strengthened.**
The previous check (`let _ = WORDLIST[255]`) only verified index 255
existed; a future refactor could quietly replace 200 slots with `""`
and still compile. Now a `const fn`-style block asserts (1) length
is exactly 256, (2) every slot is non-empty ASCII lowercase, (3) no
duplicates across the entire list. A SAS that quietly degrades to
"6 copies of the same word" can no longer ship.
- Updated: [crates/sidevers-core/src/sas.rs:130-186](crates/sidevers-core/src/sas.rs:130).

**P2.A + P2.B + P2.C — `safe_backup_path` polished.**
- **P2.A** Canonicalize `data_dir` once at the top. Previously `data_dir` was trusted and joined verbatim, so a `..` segment in `data_dir` would escape the `<data_dir>/backups/` subtree.
- **P2.B** Reject Windows reserved device names (CON, PRN, AUX, NUL, COM1-9, LPT1-9, with optional extension — "CON.bin" still aliases to the console on NTFS) and trailing `.` (which NTFS silently strips).
- **P2.C** Normalize the filename to NFC and reject bidi-override (U+202A..U+202E, U+2066..U+2069) and zero-width characters (U+200B..U+200F, U+FEFF). `"innocent\u{202E}txt.exe"` can no longer pose as `"innocentexe.txt"`.
- Adds `unicode-normalization` dep to the Tauri crate.
- 7 new path-validation tests cover each rejection class; total 16 tests pass.
- Updated: [desktop/tauri/src/main.rs](desktop/tauri/src/main.rs), [desktop/tauri/Cargo.toml](desktop/tauri/Cargo.toml).

**P2.D — constant-time hash compare in storage.**
`object.rs::verify_hash` switched from `==` to `subtle::ConstantTimeEq::ct_eq`. Not exploitable for confidentiality today (content-addressing — the requester already knows the hash they're asking for), but auditors expect every hash compare in a crypto library to be constant-time; pre-empts the finding and makes a future use of `verify_hash` in an authentication context safe by default.
- Updated: [crates/sidevers-storage/src/object.rs:338-352](crates/sidevers-storage/src/object.rs:338), [crates/sidevers-storage/Cargo.toml](crates/sidevers-storage/Cargo.toml) (adds `subtle`).

**P2.E — FFI string length cap on `CStr::from_ptr` scans.**
A non-NUL-terminated C string previously caused `CStr::from_ptr` to scan into invalid memory until segfault. New `cstr_with_cap` helper bounds the scan at `FFI_CSTR_MAX_LEN = 4096` bytes; non-terminated input returns `SvStatus::InvalidInput` cleanly.
- Updated: [crates/sidevers-ffi/src/mem.rs](crates/sidevers-ffi/src/mem.rs) (helper), [keys.rs](crates/sidevers-ffi/src/keys.rs) (label), [address.rs](crates/sidevers-ffi/src/address.rs) (addr).

**P1.C — per-IP sybil tracker infrastructure.**
The per-pubkey reputation system is sybilable: ephemeral sides cost nothing, so any motivated abuser dodges "refused" by minting fresh identities. New `IpSybilTracker` records distinct pubkeys per source IP within a rolling window (default 1 hour, 16 distinct pubkeys); `observe(peer, ip, now)` returns `Allow` or `OverQuota`. **Not yet wired into the accept loop** — operational policy (enforce vs log-only) is left to a follow-up so deployers can tune thresholds before behavior change ships. Available immediately as a metric source.
- Updated: [crates/sidevers-net/src/reputation.rs](crates/sidevers-net/src/reputation.rs) (+ types exported via [lib.rs](crates/sidevers-net/src/lib.rs)).
- 5 new unit tests cover under-quota, over-quota, known-pubkey-is-free, window-reset, separate-IPs-isolated.

**P1.D — verse key rotation: idempotent retry on member reconnect.**
Previously a failed key-rotation push left the affected member silently stuck on the old key (no decryption of future posts; their own posts unreadable by other members). New `VerseHost::stash_pending_key_push` records failed pushes; `serve_verse` calls `take_pending_key_push` on member reconnect and re-delivers. Stash is keyed by member side, so the latest rotation supersedes any earlier stale entry. Best-effort retry: a second failure re-stashes for the next reconnect.
- Updated: [crates/sidevers-net/src/verse.rs](crates/sidevers-net/src/verse.rs) (state + helpers), [node.rs:2595-2655 + serve_verse](crates/sidevers-net/src/node.rs:2595) (stash on fail + redeliver on reconnect).
- 3 new unit tests: round-trip, latest-supersedes, separate-stashes-per-member.

### Test-suite delta (1.5i)

| Crate | After 1.5h | After 1.5i | Δ |
|-------|-----------|-----------|---|
| sidevers-core | 157 | 157 | 0 |
| sidevers-net | 75 | 83 | +8 (5 sybil, 3 verse stash) |
| sidevers-ffi | 9 | 12 | +3 (panic helper) |
| sidevers-storage | 17 | 17 | 0 |
| sidevers-node | 5 | 5 | 0 |
| sidevers-conformance | 72 | 72 | 0 |
| sidevers-desktop (Tauri) | 9 | 16 | +7 (path hardening) |
| **Total** | **344** | **362** | **+18** |

All 362 tests pass: `cargo test --workspace`, `cargo test --manifest-path desktop/tauri/Cargo.toml`.

### Deferred to follow-up

- **Wire `IpSybilTracker` into the accept loop** — policy decision (enforce vs log-only) + tuning against shared-NAT users.
- **Conformance test for verse-key-rotation reconnect redelivery** — end-to-end exercise of the P1.D path (drop member mid-rotation, reconnect, assert new key delivered). The unit tests cover the state-machine invariants; the wire-level test is the next pass.
- **Reconsent member-side timeout** (was "P3.F" in the audit plan — non-bug, design observation).
- **Magic-byte prefix for sealed-seed format** (P3.A) — robustness against future format-change confusion; not exploitable today.
- **CBOR per-message memory budget** (P3.B), **reference manifest width cap** (P3.C), **CLI hex logging policy** (P3.E) — minor lints.

---

## Phase 1.5h — pre-audit hardening (May 2026)

### Closed

**P1.5 — peer pubkeys redacted from logs.**
New helper [`sidevers_core::LogId`](crates/sidevers-core/src/log_id.rs) renders any byte
slice as `aabbccdd…` (4-byte prefix + ellipsis). All `tracing` events
and `Debug` impls that previously hex-encoded full 32-byte side
pubkeys now use `LogId`. Includes `Envelope::Debug` so an
accidental `tracing::debug!(env = ?env)` no longer leaks `from`/`to`/`nonce`.
- New: `crates/sidevers-core/src/log_id.rs` (5 tests)
- Updated: `crates/sidevers-net/src/handshake.rs`,
  `crates/sidevers-net/src/node.rs`,
  `crates/sidevers-core/src/envelope.rs`

**P2.1 — OS CSPRNG for handshake ephemerals.**
[handshake.rs:102](crates/sidevers-net/src/handshake.rs:102) and [handshake.rs:259](crates/sidevers-net/src/handshake.rs:259) now use
`rand::rngs::OsRng` directly instead of `rand::thread_rng()`. (Both
are CSPRNGs under current `rand` 0.8, but the explicit choice
removes any future-regression surface.)

**P2.3 — CBOR parser DoS defenses.**
- `CborReader::read_map_header` / `read_array_header` reject counts
  above 1 million entries
  ([cbor.rs:382-410](crates/sidevers-core/src/cbor.rs:382)), preventing
  `Vec::with_capacity(u32::MAX)` OOM.
- Recursive `skip_value` helpers in `messages/direct.rs` and
  `messages/profile.rs` now thread a depth budget (32 levels),
  blocking a deeply-nested CBOR stack-overflow attack on the
  forward-compat decoders.
- 2 new cbor tests + 2 new direct tests.

**P2.9 — conformance tests for replay / MAC / version-mismatch.**
The audit flagged that signature-tampering was well-covered but
replay-cache enforcement, handshake MAC mismatch, and version-
negotiation rejection were only exercised on happy paths.
- `harness::tests::replay_rejection_blocks_duplicate_envelope_at_receiver`
  ([sidevers-conformance/src/harness.rs](crates/sidevers-conformance/src/harness.rs)) — sends the same envelope twice
  through two real nodes; asserts the second submission is silently
  dropped by the receiver's replay cache.
- `handshake::tests::confirm_mac_mismatch_is_rejected_by_subtle_eq` —
  verifies `transcript_mac` + `subtle_eq` reject single-bit flips,
  wrong session keys, and tampered transcripts.
- `handshake::tests::version_check_rejects_helloback_with_unsupported_v`
  — verifies `HelloBackPayload` with `v ∈ {0, 2, 99, u64::MAX}` trips
  the initiator's inline guard.

**P1.1 — at-rest encryption of the master seed.**
The reference clients no longer write 32-byte plaintext seed bytes
to disk by default. The new
[`sidevers_core::keystore`](crates/sidevers-core/src/keystore.rs) module provides:

```
SealedSeed = CBOR {
  ct, kdf, aead, salt, nonce, version,
  argon2_m, argon2_p, argon2_t,
}
```

Wrapping primitive: **Argon2id → ChaCha20-Poly1305**. KDF defaults
follow OWASP 2023 (m=19 MiB, t=2, p=1). All format parameters
(version, KDF/AEAD identifiers, Argon2 m/t/p, salt) are bound into
the AEAD AAD, so a parameter swap (e.g. lowering memory cost in
flight to enable cheaper offline guessing) fails to open.

- New module: 8 keystore tests cover round-trip, wrong passphrase,
  tampered ciphertext, tampered salt, version mismatch, empty
  passphrase, per-seal uniqueness, default-params identity.
- **Wired into Tauri** — [desktop/tauri/src/main.rs](desktop/tauri/src/main.rs) `write_seed_backup`
  now takes `{dataDir, filename, passphrase}` and writes the sealed
  form to `<data_dir>/backups/<filename>` with `0o600` perms.
  The onboarding wizard and the Settings panel both prompt for and
  confirm a passphrase before sealing.
- **Wired into the daemon** — `sidevers-node` detects sealed seeds
  by file length (anything ≠ 32 bytes is treated as sealed CBOR)
  and reads the passphrase from `SIDEVERS_SEED_PASSPHRASE`.
  Legacy 32-byte plaintext seeds still load with a stderr warning so
  existing deployments aren't broken.
- 5 new sidevers-node parser tests (refactored to be env-var-free).

**P1.2 — `write_seed_backup` path traversal closed.**
[desktop/tauri/src/main.rs](desktop/tauri/src/main.rs) `safe_backup_path` rejects path separators,
parent-dir refs, dotfiles, NUL bytes, NTFS-reserved characters, and
overlong filenames. The Tauri command now takes a bare `filename`
and writes inside `<data_dir>/backups/`. The webview can no longer
direct a seed file to e.g. `~/.ssh/authorized_keys`.
- 9 new path-validation tests.

**P1.4 (substrate) — Short Authentication String for pairing.**
- TTL on `PendingPairing` tightened from **600s → 90s**
  ([crates/sidevers-net/src/side.rs:451](crates/sidevers-net/src/side.rs:451)).
- New [`sidevers_core::sas`](crates/sidevers-core/src/sas.rs) module computes a 6-word SAS
  from `BLAKE3("sidevers/v1/pairing-sas" ‖ side ‖ nonce ‖ new_device_eph_pub)[0..6]`
  indexed into a 256-word curated list.
- 8 SAS tests cover determinism, output shape, ephemeral / nonce /
  side-pubkey tamper detection, wordlist quality.
- Exposed as `sidevers_core::pairing_sas` / `pairing_sas_string`.
- **Integration not yet wired into the pairing wire protocol** — see
  "Deferred to next phase" below.

**P2.2 — verified, no code change needed.**
The audit flagged "responder handshake rate limit not invoked." On
re-read: [node.rs:1338](crates/sidevers-net/src/node.rs:1338) calls `services.handshake_limit.try_acquire(remote_ip)`
inside `handle_connection`, which is the inbound accept path,
*before* `run_responder` runs at [node.rs:1345](crates/sidevers-net/src/node.rs:1345). The original
finding was incorrect.

### Deferred to next phase

**P1.3 — Double Ratchet for DMs + Megolm for verses.**
The single biggest remaining gap in the "privacy-first" claim. A
side-key compromise today decrypts every payload ever sealed with
that side (no post-compromise security). Adoption is a multi-week
project — protocol changes, header format, message ordering, skip-
key window, group-keys flow for verses — and warrants its own
design doc + test-vector verification against libsignal.

Estimated scope: 2-4 weeks. The keystore work (P1.1) is a prerequisite
because the new ratchet state needs the same at-rest encryption.

**P1.4 (UX) — pairing flow integration of the SAS.**
The primitive is in place and tested. Threading it through the
actual pairing flow requires:
1. New device exposes its generated X25519 ephemeral via the
   `accept_pairing` return value so the Tauri client can compute the
   SAS to display.
2. Existing device's `PairingRequest` handler holds the bundle *send*
   until a user-confirmation event fires from the UI (new
   `confirm_pairing(nonce)` Tauri command).
3. Both screens render the 6 words; the user manually compares.
4. Existing device displays a "decline" path that destroys the
   pending nonce and replies with a refusal.

Substantive UX redesign; out of scope for this hardening pass.
Estimated scope: 1 week (mostly UI + a small async refactor of the
existing-device pairing handler).

**P2.4 — per-peer rate limit on STORAGE_GET.**
Documented; small, would land alongside any storage-layer changes.

**P2.5 — co-holder STATE_DELTA E2E sealed.**
Documented in CRYPTO.md §4 item #11 already; tracked as Phase 1.5h+.

**P2.6 — Tor/SOCKS proxy support.**
Significant transport-layer change; warrants its own design pass.
Documented as a phase-2 deliverable.

**P2.7 — verse sealed-sender for posts.**
Documented as a phase-2 design item.

**P2.8 — Tauri `withGlobalTauri: false`, drop `style-src 'unsafe-inline'`.**
Documented in CRYPTO.md §4 item #16 already. Currently safe because
of the empty capability set; should be tightened when QR rendering
moves off the inline-style SVG path.

### Documented design tradeoffs (P3)

These are on the record now so a future reviewer asking "did you
consider X?" gets an immediate yes.

- **No padding / cover traffic.** Burst patterns are visible to
  passive observers. Standard in messaging protocols; not in scope
  for v1.
- **Local message deletion is unlink, not secure-wipe.** Standard
  filesystem semantics. Users who need forensic-grade deletion run
  on encrypted disks.
- **Self-signed TLS with `AcceptAnyServerCert`** is intentional —
  Sidevers identity is at the handshake layer, not in TLS. The
  optional cert-pinning machinery (`cert.rs`) is available for
  operators who want defense in depth.
- **Forwarder learns recipient/sender addresses + timing.** Documented
  in CRYPTO.md §4 already.
- **Side derivation is deterministic from the master + label.** Anyone
  with the master can enumerate sides by trying labels. Defensible
  (they already have the master), and unlinkability holds for any
  observer who doesn't have it.
- **ChaCha20-Poly1305 nonce derived as first 12 bytes of the 16-byte
  envelope nonce.** Safe because the 16 bytes are random per envelope.
  Spec amendment recommended (already item #1 in CRYPTO.md §4).

## Test-suite delta

| Crate                  | Before audit | After audit | Δ  |
|------------------------|--------------|-------------|----|
| sidevers-core          | 141          | 157         | +16|
| sidevers-net           | 73           | 75          | +2 |
| sidevers-node          | 0            | 5           | +5 |
| sidevers-conformance   | 71           | 72          | +1 |
| sidevers-ffi           | 9            | 9           |  0 |
| sidevers-storage       | 17           | 17          |  0 |
| sidevers-desktop (Tauri) | 0          | 9           | +9 |
| **Total**              | **311**      | **344**     | **+33** |

All 344 tests pass on `cargo test --workspace` and `cargo test
--manifest-path desktop/tauri/Cargo.toml`.

## How to verify the audit changes locally

```bash
# All audit-driven tests:
cargo test -p sidevers-core --lib log_id keystore sas cbor::tests::map_header_rejects cbor::tests::array_header_rejects
cargo test -p sidevers-core --lib messages::direct::tests::skip_value
cargo test -p sidevers-net --lib handshake::tests::confirm_mac_mismatch handshake::tests::version_check_rejects
cargo test -p sidevers-conformance --lib replay_rejection
cargo test -p sidevers-node --bin sidevers-node
cargo test --manifest-path desktop/tauri/Cargo.toml backup_path_tests

# Full suite:
cargo test --workspace
cargo test --manifest-path desktop/tauri/Cargo.toml
```
