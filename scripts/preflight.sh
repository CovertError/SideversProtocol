#!/usr/bin/env bash
# scripts/preflight.sh — run the same three gates CI enforces, locally.
#
# Mirrors `.github/workflows/ci.yml` jobs `fmt`, `clippy`, `test` so a
# clean local run guarantees the corresponding CI jobs will pass. Use
# this before `git push`; the companion `.githooks/pre-push` hook calls
# it for you once installed.
#
# Usage:
#   bash scripts/preflight.sh                  # run all three gates
#   bash scripts/preflight.sh --install-hooks  # wire up the pre-push hook
#   bash scripts/preflight.sh --help
#
# Environment:
#   SKIP_PREFLIGHT=1   When set, the pre-push hook short-circuits to a
#                      no-op. Intended for emergency pushes to throwaway
#                      branches — never use on a push to main.
#
# Exit codes:
#   0 = all gates passed (or --install-hooks succeeded)
#   1 = at least one gate failed; failing gate is reported in the summary
#   2 = invocation error (bad flag, cargo not on PATH, not in a repo)

set -u
set -o pipefail

# The user's cargo lives in ~/.cargo/bin on this machine; rustup-installed
# cargo isn't always on the default shell PATH (especially under git hooks
# which inherit a sparse env). Prepend defensively; no-op if already there.
case ":$PATH:" in
    *":$HOME/.cargo/bin:"*) ;;
    *) PATH="$HOME/.cargo/bin:$PATH" ;;
esac
export PATH

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
    sed -n '2,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

install_hooks() {
    if ! git -C "$REPO_ROOT" rev-parse --git-dir >/dev/null 2>&1; then
        echo "error: $REPO_ROOT is not a git repository" >&2
        exit 2
    fi
    git -C "$REPO_ROOT" config core.hooksPath .githooks
    echo "==> core.hooksPath set to .githooks"
    echo "==> Future 'git push' invocations will run preflight automatically."
    echo "==> To bypass once: SKIP_PREFLIGHT=1 git push"
    echo "==> To uninstall:   git -C $REPO_ROOT config --unset core.hooksPath"
}

case "${1:-}" in
    -h|--help) usage; exit 0 ;;
    --install-hooks) install_hooks; exit 0 ;;
    "") ;;
    *) echo "error: unknown flag '$1' (try --help)" >&2; exit 2 ;;
esac

if ! command -v cargo >/dev/null 2>&1; then
    echo "error: cargo not found on PATH (looked in \$HOME/.cargo/bin too)" >&2
    exit 2
fi

cd "$REPO_ROOT"

# Track failures across all three gates so the developer sees everything
# that's broken in one run, not just whatever happened to fail first.
# Mirrors CI's fail-fast: false matrix behavior for the test job.
FAILED=()

run_gate() {
    local name="$1"; shift
    echo
    echo "==> [$name] $*"
    if "$@"; then
        echo "==> [$name] PASS"
    else
        echo "==> [$name] FAIL" >&2
        FAILED+=("$name")
    fi
}

run_gate "fmt"     cargo fmt --all -- --check
run_gate "clippy"  cargo clippy --workspace --all-targets -- -D warnings
run_gate "test"    cargo test --workspace --all-targets

echo
if [ "${#FAILED[@]}" -eq 0 ]; then
    echo "==> preflight: ALL GATES PASSED"
    exit 0
else
    echo "==> preflight: FAILED (${FAILED[*]})" >&2
    exit 1
fi
