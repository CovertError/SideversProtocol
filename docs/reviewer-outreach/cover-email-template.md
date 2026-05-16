# Cover email template — Phase 2.5 external cryptography review

This is the message to send to a candidate cryptographer when handing
them the audit bundle. Tailor the opening paragraph + the "why you in
particular" line per candidate.

---

## Subject

`Sidevers Phase 2.5 — cryptography review handoff (Rust, ~1 week
estimate, paid)`

## Body

Hi [Name],

I'm Omar from Cyberagora (Saudi Arabia) — I've spent the last several
months building **Sidevers**, a peer-to-peer messaging protocol +
reference implementation in Rust. The cryptographic surface is locked
in (Ed25519, X25519, BLAKE3, ChaCha20-Poly1305, HKDF-SHA512); I'd like
an independent reviewer to validate that the *implementation* faithfully
realizes those choices and doesn't introduce vulnerabilities.

**Why you specifically:** [one-line — e.g. "you've worked extensively
on rustls and have published on TLS implementation bugs" or "you
maintain ed25519-dalek and your write-up of the malleability fix
informed our handshake design."]

### Scope

- **In scope:** Phase 1 (network protocol, handshake, envelope,
  replay, storage, discovery, operational hardening) + Phase 1.5
  (verses, multi-side, multi-device pairing). ~30k lines of Rust;
  293 workspace tests; 32 fuzz harnesses; iOS cross-compile clean.
- **NOT in scope:** the spec's design choices (the protocol designer
  made those — I'm asking you to confirm the implementation matches),
  or Phase 2 (a separate Laravel registry, different repo).

### What I'd like from you

1. **Implementation correctness** — does the code actually do what the
   spec says? Tampering, replay, signature verification, transcript
   binding, forward secrecy on key rotation, etc.
2. **Independent verdict on a small handful of judgment calls** —
   listed concretely in §4 of CRYPTO.md and in the briefing.
3. **A short report** — find / no-find / "I'd recommend X." Bullet
   points are fine. Severity-tagged.

### The package

Attached is `sidevers-audit-YYYYMMDD.tar.gz` (~4 MiB). Extract it,
then read in this order:

1. `sidevers/REVIEWER_BRIEFING.md` — orientation (5 min)
2. `sidevers/CRYPTO.md` — implementation map (15 min skim)
3. `sidevers/audit-logs/` — pre-captured `cargo test` / `cargo
   clippy` / `cargo check --target aarch64-apple-ios` output so
   you can compare against your own runs.

To verify the bundle runs cleanly on your machine:

```sh
tar xzf sidevers-audit-YYYYMMDD.tar.gz && cd sidevers
cargo test --workspace                    # ~3 seconds, should match audit-logs/test.log
cargo clippy --workspace --all-targets    # should be clean
```

### Estimate + compensation

I'm budgeting roughly **one week of your time** at your standard
rate. Open to a fixed-fee or hourly arrangement — happy to discuss
on a quick call.

### Logistics

- Spec PDF (100 pages, six bundled docs) sent separately on request —
  it's not in the bundle because it's not GPL-compatible with the
  code license.
- I'm in Riyadh (UTC+3) but flexible.
- Findings can be sent informally as you go; final report whenever
  works for you.

If this fits, reply with your rate + a rough start window and I'll
send the spec PDF + any clarifications you need.

Thanks for considering it.

— Omar
omar@cyberagora.sa
