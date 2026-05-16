# Candidate reviewer shortlist — Phase 2.5

A starting set, ranked by fit for this codebase's specific
crypto + Rust profile. None of these are pre-vetted; you'll need
to reach out, confirm availability + budget alignment, and pick.

## Fit criteria

What matters for this review:

- **Rust fluency at the cryptographic-library level** — they should
  be able to read `ed25519-dalek` / `x25519-dalek` / `rustls`
  internals without needing to ramp.
- **Protocol-implementation review experience** — auditing protocols
  is different from auditing primitives. Wire-format invariants,
  replay windows, transcript binding, key rotation — these are the
  questions we're asking.
- **Comfortable saying "the spec is unclear, here's what I'd
  recommend"** — we explicitly call out spec gaps (especially §3.4
  AEAD nonce derivation) and want an independent recommendation.
- **Available within ~3 months** — Phase 2 is gated on this.
- **English working language** OK; Arabic a bonus, not required.

## Tier 1 — reviewers I'd reach out to first

### Trail of Bits
- **Why:** Their Rust + cryptography practice is the most established
  in the industry. They've audited libsignal, MaidSafe Routing,
  multiple PQ schemes, Zcash. Cryptography Services group is exactly
  the right shape for this work.
- **How:** https://www.trailofbits.com/contact/ — request a scoping
  call, describe Phase 1 + 1.5 surface, ask for a 1-week assessment
  quote.
- **Estimated cost:** $25–60k for a one-week engagement based on
  public rate cards. High but the most defensible vendor choice
  for an external review.
- **Lead time:** typically 4–8 weeks.

### NCC Group Cryptography Services
- **Why:** Strong protocol-review track record (audited Tor,
  WireGuard, parts of Signal). Independent + reputable.
- **How:** https://www.nccgroup.com/contact-us/ — request a
  conversation with the Cryptography Services practice lead.
- **Estimated cost:** comparable to Trail of Bits.
- **Lead time:** typically 6–10 weeks.

### Filippo Valsorda (independent)
- **Why:** Maintains Go cryptography for the Go core team; deep
  Ed25519 / X25519 / TLS protocol-implementation expertise; author
  of multiple public protocol-implementation analyses. Independent
  consultant; takes single-engagement work.
- **How:** Email via https://filippo.io/ contact form. Mention you
  read his Ed25519 malleability writeup if it informed the design.
- **Estimated cost:** independent rates; quote-on-request, generally
  more accessible than a firm.
- **Lead time:** depends on his current commitments; could be quick
  or take months.

## Tier 2 — strong candidates with adjacent expertise

### isislovecruft (Isis Lovecruft) — Brave Research / dalek-cryptography
- **Why:** Author of `ed25519-dalek` and `x25519-dalek` — the two
  primitives our handshake + signature paths rest on. Direct insight
  into edge cases.
- **How:** Reach via GitHub or the dalek-cryptography Matrix room.
  May or may not take engagement work directly; if not, ask for a
  referral.

### Brian Smith — Briansmith.org / `ring` maintainer
- **Why:** Maintains `ring`, the crypto provider under `rustls` (so
  also under our QUIC stack via `quinn`). Knows the
  Rust-cryptography-stack interactions cold.
- **How:** Contact form at briansmith.org.

### Sean Bowe — Electric Coin Co / Halo2
- **Why:** Significant Rust cryptography track record (Zcash sapling,
  Halo2). Pragmatic protocol-review style.
- **How:** Via GitHub or ECC channels.

## Tier 3 — academic / research

If a peer-reviewed academic angle is desirable (more rigorous, longer
turnaround):

- **The Cryptography Group at INRIA (Paris)** — particularly the team
  around Karthikeyan Bhargavan; they did the F* miTLS proofs.
- **Real World Crypto** community (rwc.iacr.org) — the program
  committee includes people who do this kind of review work; some
  take consulting on the side.

## Process suggestion

1. **Week 1:** send the cover email (template at
   [cover-email-template.md](cover-email-template.md)) to Trail of
   Bits + Filippo Valsorda + one other. Don't send to all three
   firms at once — the offers will overlap awkwardly.
2. **Week 2–3:** scoping calls, narrow to one.
3. **Week 4+:** ship the bundle, await report.
4. **Post-report:** triage findings, file follow-up issues, address
   anything critical before public launch.

## After the review

- Address critical / high findings before any public launch.
- Publish the report (or an executive summary) alongside the v1.0
  release — being explicit about what was reviewed is itself a
  trust signal.
- Plan a Phase 4.5 follow-on review when the Phase 2 registry +
  Phase 3 mobile client land (different surface, different threat
  model).
