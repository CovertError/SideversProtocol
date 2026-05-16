#!/usr/bin/env bash
# scripts/audit-bundle.sh — Phase 2.5 reviewer handoff bundle.
#
# Produces a single tarball that a reviewer can `tar xzf` into a fresh
# directory and immediately run `cargo test --workspace` on. Includes:
#
#   * The full repo source (a `git archive`, so tracked files only —
#     no `target/`, no editor cruft).
#   * CRYPTO.md (implementation map)
#   * REVIEWER_BRIEFING.md (this directory's audit briefing)
#   * The current `cargo fmt --check`, `cargo clippy`, and
#     `cargo test --workspace` outputs, so the reviewer can compare
#     against their own runs.
#   * A short README that names the reviewer-suggested reading order.
#
# Usage:
#   bash scripts/audit-bundle.sh             # → /tmp/sidevers-audit-YYYYMMDD.tar.gz
#   bash scripts/audit-bundle.sh out.tar.gz  # → ./out.tar.gz
#
# Exit codes:
#   0 = bundle created, embedded test results all green
#   1 = something during the build / test pass failed; bundle still
#       written (with failing logs included) for the reviewer's
#       inspection

set -u
set -o pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

OUT="${1:-/tmp/sidevers-audit-$(date -u +%Y%m%d).tar.gz}"
STAGE="$(mktemp -d -t sidevers-audit.XXXXXX)"
trap 'rm -rf "$STAGE"' EXIT

echo "==> Repo root: $REPO_ROOT"
echo "==> Stage dir: $STAGE"
echo "==> Output:    $OUT"

# 1. Source snapshot via `git archive` (respects .gitignore + only
#    includes tracked files — no target/ / no node_modules / no
#    editor cruft).
echo "==> Capturing source via git archive..."
git archive --format=tar --prefix=sidevers/ HEAD | tar -x -C "$STAGE"

BUNDLE_DIR="$STAGE/sidevers"

# 2. Run the verification pipeline. Capture everything into a logs/
#    subdir of the bundle.
mkdir -p "$BUNDLE_DIR/audit-logs"
ALL_GREEN=1

echo "==> cargo fmt --all --check..."
if cargo fmt --all -- --check > "$BUNDLE_DIR/audit-logs/fmt.log" 2>&1; then
    echo "    OK"
else
    echo "    FAILED — see audit-logs/fmt.log"
    ALL_GREEN=0
fi

echo "==> cargo clippy --workspace --all-targets..."
if cargo clippy --workspace --all-targets > "$BUNDLE_DIR/audit-logs/clippy.log" 2>&1; then
    echo "    OK"
else
    echo "    FAILED — see audit-logs/clippy.log"
    ALL_GREEN=0
fi

echo "==> cargo test --workspace..."
if cargo test --workspace > "$BUNDLE_DIR/audit-logs/test.log" 2>&1; then
    PASSING=$(grep -E "^test result:" "$BUNDLE_DIR/audit-logs/test.log" \
              | awk '{sum+=$4} END {print sum}')
    echo "    OK — $PASSING passing"
else
    echo "    FAILED — see audit-logs/test.log"
    ALL_GREEN=0
fi

# iOS cross-compile (skip silently on non-macOS / no toolchain).
if rustup target list --installed 2>/dev/null | grep -q aarch64-apple-ios; then
    echo "==> cargo check --target aarch64-apple-ios (library crates)..."
    if cargo check --target aarch64-apple-ios \
        -p sidevers-core -p sidevers-storage -p sidevers-net \
        -p sidevers-conformance -p sidevers-ffi \
        > "$BUNDLE_DIR/audit-logs/ios-check.log" 2>&1; then
        echo "    OK"
    else
        echo "    FAILED — see audit-logs/ios-check.log"
        ALL_GREEN=0
    fi
else
    echo "==> Skipping iOS cross-compile (aarch64-apple-ios target not installed)"
fi

# 3. Write the bundle README pointing the reviewer at the entry points.
cat > "$BUNDLE_DIR/AUDIT-README.md" <<'EOF'
# Sidevers Phase 2.5 audit bundle

This is the self-contained handoff for the external cryptography
review.

## Start here

1. `REVIEWER_BRIEFING.md` — orientation: what you've been asked to do,
   threat model, 30-minute walkthrough, scope boundaries.
2. `CRYPTO.md` — implementation map (spec section → file/function),
   primitives in use, known limitations.
3. The spec PDF lives at `~/Downloads/sidevers-complete_3.pdf` on the
   author's machine; if you don't have a copy, request one from
   omar@cyberagora.sa.

## Verify the bundle

```sh
cd sidevers
cargo test --workspace    # should match audit-logs/test.log
cargo clippy --workspace --all-targets  # should be clean
```

`audit-logs/` contains the build's own test + clippy + fmt outputs at
bundle time, so you can compare against your run.

## Reaching the author

omar@cyberagora.sa — please use subject prefix
`Sidevers Phase 2.5 — <severity>: <one-line>`.
EOF

# 4. Tarball.
echo "==> Compressing bundle..."
tar -czf "$OUT" -C "$STAGE" sidevers
SIZE_MB=$(du -m "$OUT" | awk '{print $1}')
echo "==> Wrote $OUT (${SIZE_MB} MiB)"

if [ "$ALL_GREEN" -eq 1 ]; then
    echo "==> All checks green."
    exit 0
else
    echo "==> WARNING: at least one check failed; see audit-logs/ in the bundle."
    exit 1
fi
