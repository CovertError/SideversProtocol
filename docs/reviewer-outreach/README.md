# Phase 2.5 reviewer outreach

This folder is the operational checklist for getting an external
cryptographer engaged. Contents:

- **`candidate-shortlist.md`** — ranked starting set of reviewers
  (firms + independents) with rationale, contact paths, and rough
  cost / lead-time estimates.
- **`cover-email-template.md`** — the message to send. Tailor the
  one-liner about why-you-specifically, attach the bundle, hit send.

## What to do

1. **Generate a fresh audit bundle:**
   ```sh
   bash scripts/audit-bundle.sh /tmp/sidevers-audit-$(date -u +%Y%m%d).tar.gz
   ```
   The script's exit code is 0 only if `cargo fmt --check` + `clippy`
   + `cargo test --workspace` + iOS cross-compile are ALL clean.
   Don't send the bundle if it isn't.

2. **Pick 1–3 candidates** from `candidate-shortlist.md`. Don't send
   to multiple firms simultaneously — competing offers get awkward.

3. **Tailor the cover email** (`cover-email-template.md`) per
   candidate, attach the bundle, send.

4. **Track responses** in whatever you use for ops. When one
   accepts, archive the others gracefully ("we've moved forward
   with another reviewer; happy to revisit in future").

5. **After the report:** triage, file follow-up issues, address
   critical/high findings before the public Phase 1 release.

## Bundle location

The most recent generated bundle: ask the operator (typically lives
under `/tmp/` or `~/Downloads/`; not checked into the repo because
of size + the audit-logs/ subdirectory being a per-run snapshot).
