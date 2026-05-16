# Sidevers Protocol — Reference Node

Rust implementation of the Sidevers v1 protocol. **Phase 1** + **Phase 1.5
Verses** are complete; the desktop reference client (**Phase 3**) is
usable end-to-end. Phase 2 (Laravel public-layer registry) lives in a
separate repo. Phase 2.5 (external cryptography review) is in prep —
see [REVIEWER_BRIEFING.md](REVIEWER_BRIEFING.md).

**Internal — not for distribution.**

## What is Sidevers?

A peer-to-peer protocol for messaging the people you've chosen to talk
to, without a server in the middle. Each identity is a self-sovereign
**side** — you hold the keys, your data lives where you tell it to,
no platform owns your reach. Sides are unlinkable by design: a "work"
side and a "private" side are independent identities that a peer
can't trivially correlate.

The runtime is a Rust node that speaks QUIC + a signed-CBOR envelope
format on top. A small Tauri desktop client (and a CLI) ships in this
repo as the reference user-facing surface. Mobile FFI exists; mobile
clients are Phase 3.F (not in this repo).

## Status snapshot

- **Wire surface:** Phase 1 (handshake, direct messaging, storage,
  discovery) + Phase 1.5 (verses, multi-side, multi-device pairing,
  multi-moderator) complete. Phase 2 public-layer payload codecs
  (HandleResolve / HandleAttest / PagePublish / PageFetch /
  PageDeliver / Announcement / DirectoryEntry) shipped as scaffold —
  no `serve_public` handler because Phase 2 dispatch is Laravel-side.
- **Tests:** `cargo test --workspace` = 293 passing across 5 crates.
- **Fuzz:** 32 harnesses under `fuzz/fuzz_targets/`; nightly CI
  workflow at [.github/workflows/fuzz.yml](.github/workflows/fuzz.yml).
- **Cross-platform:** library crates cross-compile clean for
  `aarch64-apple-ios`, Android, and all desktop targets.
- **Hardening:** per-source-IP handshake rate limit, persisted +
  bounded replay cache, TLS cert pinning (opt-in), per-publisher
  storage retract provenance, gossip-fanout web-of-trust filter
  (opt-in), Prometheus `/metrics` endpoint, NAT hole-punching
  (cone NATs), filesystem permissions chmod 0o600 on every SQLite
  store, production-grade Tauri CSP.

For the complete cryptographic + operational map, see
[CRYPTO.md](CRYPTO.md).

---

## I'm a user — how do I use Sidevers?

### Install + first run (desktop)

```sh
# Build the Tauri desktop client.
cd desktop/tauri
cargo tauri dev          # development run
# OR
cargo tauri build        # production bundle
```

First launch hits an **onboarding wizard** (5 screens):

1. **Welcome.** Explains what Sidevers is.
2. **Pick a data directory.** Pre-filled with the OS-appropriate
   default (`~/Library/Application Support/Sidevers` on macOS,
   `~/.local/share/sidevers` on Linux, `%APPDATA%/Sidevers` on
   Windows). Keys + inbox live here.
3. **Create your first side.** Pick a label (`work`, `private`,
   `public`, `close` — opaque to the protocol, meaningful to you).
4. **Back up your seed.** Choose a file path. Sidevers writes the
   32-byte seed there at owner-only permissions (mode 0o600). This
   is the only copy of your private key. Lose it and you lose the
   identity.
5. **Done.** Your address is shown. Hand it to someone you'd like
   to message.

### Day-to-day flows

#### Sending a direct message

1. From the **Hosted sides** panel, click the side you want to
   send from to make it active.
2. Paste the recipient's listen address in **Dial peer**, click
   **Connect**.
3. Type your message in **Send a DM**, click **Send**.

The recipient's node verifies the signature, decrypts via X25519
ECDH, and the message appears in their **Inbox** panel — newest
first. The inbox is persisted to SQLite so it survives an app
restart.

#### Pairing another device

If you want the same identity on your phone or a second laptop:

1. On the device that already holds the side: click **Generate
   pairing QR** (active side). A QR + a `sidevers-pair:1:…` URI
   appear. Valid for 10 minutes.
2. On the new device (after onboarding): paste the URI into
   **Accept pairing**. The new device becomes a co-holder of the
   same side. Both can now send and receive on its behalf.

The pairing flow uses a one-time nonce to prevent intercept, and
the new device receives a sealed state bundle (profile,
relationships, retired-sides observations) so its view matches.

#### Hosting multiple sides

Add as many sides as you want from **Hosted sides → Add side**.
Each side gets its own QUIC endpoint (no traffic multiplexing
per spec §7.6), its own listen address, and its own peer
session map. Click any side to make it the active one — Connect,
Send DM, and Pair operate on the active side.

#### Retiring a side

When a side has outlived its purpose, hit **Retire side** on its
row. The node signs a `SideRetirement` record and flips the
side's lifecycle to `Retired`. Peers receiving new envelopes
from a retired side see a documented anomaly indicator.

#### Switching languages

The topbar `<select>` toggles between English and Arabic. The
layout flips automatically (`<html dir="rtl">`) for Arabic.
Adding a locale is dropping a `dist/locales/<lang>.json` mirror
of `en.json` (and an entry in `dist/i18n.js`'s `SUPPORTED`).

### CLI (headless / scripting)

```sh
# Onboard a fresh side without the GUI.
sidevers side add --data-dir ~/sidevers-cli --label work
sidevers side add --data-dir ~/sidevers-cli --label private
sidevers side list --data-dir ~/sidevers-cli
# LABEL    ADDRESS                                LIFECYCLE  RETIRED
# work     sv1...                                 Created    no
# private  sv1...                                 Created    no

# Retire a side.
sidevers side retire --data-dir ~/sidevers-cli \
  --side ~/sidevers-cli/work.seed --reason "moving to new identity"

# Headless: send a DM to a peer.
sidevers dm send --side ~/sidevers-cli/work.seed \
  --to sv1<recipient-address> --host 1.2.3.4:50001 --text "hello"
```

The CLI offers everything the desktop client does plus envelope
sign/verify, linkage proofs, and standalone storage ops. Run
`sidevers --help` for the full surface.

---

## I'm a developer — where do I look?

### Workspace layout

```
crates/
├── sidevers-core/        # protocol types, envelope, deterministic CBOR, crypto (no I/O)
├── sidevers-storage/     # content-addressed object storage (BLAKE3 + SQLite + blob FS)
├── sidevers-net/         # QUIC transport, handshake, peers, NAT, gossip, persistence
├── sidevers-node/        # the daemon binary
├── sidevers-cli/         # CLI: keygen, addr, envelope, linkage, multi-side ops
├── sidevers-conformance/ # spec-conformance test harness
└── sidevers-ffi/         # C ABI surface for mobile (header at include/sidevers.h)
desktop/tauri/            # Tauri 2 desktop reference client (vanilla HTML/JS, no bundler)
fuzz/                     # cargo-fuzz target crate (32 harnesses, nightly Rust)
```

### Building + testing

```sh
cargo build --release                          # all crates
cargo test --workspace                         # 293 tests; ~3 s
cargo clippy --workspace --all-targets         # lint; tightened workspace lints
cargo check --target aarch64-apple-ios \       # iOS cross-compile
  -p sidevers-core -p sidevers-storage \
  -p sidevers-net -p sidevers-conformance \
  -p sidevers-ffi
cargo bench --no-run -p sidevers-core          # criterion benches compile
```

### Quick docs map

- [CRYPTO.md](CRYPTO.md) — implementation map (spec § → file/function),
  primitives in use, known limitations.
- [REVIEWER_BRIEFING.md](REVIEWER_BRIEFING.md) — orientation for an
  external cryptography reviewer (Phase 2.5).
- [scripts/audit-bundle.sh](scripts/audit-bundle.sh) — one command
  produces a self-contained tarball for the reviewer.
- [.github/workflows/fuzz.yml](.github/workflows/fuzz.yml) — nightly
  fuzz harness sweep.

### Running the reference Tauri client

```sh
cd desktop/tauri
cargo tauri dev
# Two-node demo: open a second terminal and run another instance with
# `--data-dir /tmp/sidevers-bob`. Use one as the QR-generator, the
# other to accept-pair, and you've reproduced multi-device co-hosting.
```

### Embedding the protocol

The `sidevers-net::Node` struct is the integration point. Two
process-lifetime patterns:

```rust
// Daemon: one node per data dir, run forever.
let side = MasterKey::generate()?.derive_side(&"work".into())?;
let node = Arc::new(
    Node::start(side, "0.0.0.0:50001".parse()?, Path::new("./data")).await?
);
while let Some(dm) = node.next_direct_message().await {
    println!("from {:?}: {}", dm.envelope.from,
             String::from_utf8_lossy(&dm.plaintext));
}

// Transient (one-shot ops, like the CLI's `dm send`):
let node = Node::start(side, "127.0.0.1:0".parse()?, &tempdir).await?;
let session = node.dial(peer_addr, Intent::Direct).await?;
sidevers_net::send_dm(&session, node.side(), b"hi").await?;
node.shutdown().await;
```

For the mobile C ABI surface, see
[crates/sidevers-ffi/include/sidevers.h](crates/sidevers-ffi/include/sidevers.h).

---

## Roadmap

| Phase | Status | Scope |
|-------|--------|-------|
| **1** — Rust reference node | ✅ done | Wire protocol §§2–6, handshake, replay, storage, discovery, operational hardening |
| **1.5** — Verses | ✅ done | Verse contracts, multi-side hosting, multi-device pairing, multi-moderator, amendment classification, policy machinery |
| **2** — Public layer (sidevers.com Laravel registry) | 🔜 next phase | Wire codecs scaffolded in this repo; registry dispatch is a separate repo |
| **2.5** — External cryptography review | 📦 packaged, awaiting reviewer | [REVIEWER_BRIEFING.md](REVIEWER_BRIEFING.md) + audit bundle ready |
| **3** — Clients | 🟡 in progress | Tauri desktop done (multi-side, pairing, inbox, lifecycle, i18n, onboarding wizard). CLI done. Mobile FFI ready; Flutter client not yet built. |
| **4+** — Mobile clients, code signing, distribution | future | Outside this repo |

## License

- Source code: PolyForm Noncommercial 1.0.0 — see [LICENSE-CODE](LICENSE-CODE).
- Protocol specification: CC BY-NC-SA 4.0 (in the spec document, not this repo).
- Commercial license: contact `licensing@sidevers.com`.

See the Licensing & Openness document in the project's docs set for the
full position.

## Contact

- Author: Omar @ Cyberagora (omar@cyberagora.sa)
- Phase 2.5 review handoff or security issues:
  same email, subject `Sidevers Phase 2.5 — <severity>: <one-line>`
