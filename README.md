# Sidevers Protocol — Reference Node

Rust implementation of the Sidevers v1 protocol. This is **Phase 1** of the
project: the reference node. Months 2–4 of a 24-to-36-month roadmap toward
General Availability.

**Internal — not for distribution.**

## Workspace

```
crates/
├── sidevers-core/        # protocol types, envelope, deterministic CBOR, crypto (no I/O)
├── sidevers-storage/     # content-addressed object storage (Month 3)
├── sidevers-net/         # QUIC transport, handshake, peers, NAT, gossip (Months 3–4)
├── sidevers-node/        # the daemon binary
├── sidevers-cli/         # CLI: keygen, addr, envelope, linkage
└── sidevers-conformance/ # spec-conformance test harness
```

## Building

```
cargo build --release
cargo test --workspace
```

The CLI is installed as `sidevers` in `target/release/`. Try:

```
sidevers keygen master --out alice.seed
sidevers keygen side --master alice.seed --label work --out alice-work.seed
sidevers addr --seed alice-work.seed
sidevers envelope sign --side alice-work.seed --text "hi" --out msg.bin
sidevers envelope verify msg.bin
```

## License

- Source code: PolyForm Noncommercial 1.0.0 — see [LICENSE-CODE](LICENSE-CODE).
- Protocol specification: CC BY-NC-SA 4.0 (in the spec document, not this repo).
- Commercial license: contact `licensing@sidevers.com`.

See the Licensing & Openness document in the project's docs set for the
full position.
