#!/usr/bin/env bash
#
# Driver for the Sidevers desktop client (Tauri 2). Wraps the most common
# tauri-cli commands so the entrypoint matches mobile/build-android.sh and
# mobile/build-ios.sh in style.
#
# Usage:
#   ./desktop/build-desktop.sh              # equivalent to `tauri dev`
#   ./desktop/build-desktop.sh dev
#   ./desktop/build-desktop.sh build        # production build (needs icons)
#   ./desktop/build-desktop.sh build --debug
#
# Requirements:
#   - Rust toolchain (workspace already pins MSRV)
#   - A C toolchain (cc/clang) — Tauri's deps build native code
#   - On Linux: webkit2gtk + libgtk-3-dev (see Tauri prerequisites)
#   - On macOS: Xcode CLI tools
#   - On Windows: WebView2 (preinstalled on Win11) + MSVC
#
# This script auto-installs tauri-cli if it's missing.
#
# macOS code signing (release builds only):
#   When subcommand is `build` on macOS, the script REQUIRES the Apple
#   Developer ID env vars below to be set. Tauri picks them up
#   automatically and produces a signed, notarized, stapled .app/.dmg
#   that opens cleanly on every Mac (no Gatekeeper warning).
#
#     APPLE_SIGNING_IDENTITY   "Developer ID Application: <Name> (TEAMID)"
#     APPLE_ID                 your Apple ID email
#     APPLE_PASSWORD           app-specific password from appleid.apple.com
#     APPLE_TEAM_ID            10-character team ID from developer.apple.com
#
#   See docs/RELEASING.md → "macOS code signing" for the one-time setup.
#
#   Override by passing UNSIGNED=1 to build a local unsigned .app for
#   development. UNSIGNED .apps trip Gatekeeper; never ship one.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TAURI_DIR="$REPO_ROOT/desktop/tauri"

if ! command -v cargo-tauri &> /dev/null; then
    echo "==> Installing tauri-cli (^2)"
    cargo install tauri-cli --version "^2"
fi

# Default subcommand is `dev` so a bare invocation hot-runs the app.
SUBCMD="${1:-dev}"
shift || true

# macOS release builds: enforce signing creds. The four env vars below
# are read directly by Tauri's bundler (and by tauri-action in CI), so
# we don't pass them through — we just verify they're present and bail
# early with an actionable message if not.
if [[ "$(uname -s)" == "Darwin" && "$SUBCMD" == "build" && "${UNSIGNED:-}" != "1" ]]; then
    missing=()
    for var in APPLE_SIGNING_IDENTITY APPLE_ID APPLE_PASSWORD APPLE_TEAM_ID; do
        if [[ -z "${!var:-}" ]]; then
            missing+=("$var")
        fi
    done
    if (( ${#missing[@]} > 0 )); then
        cat >&2 <<EOF
==> ERROR: macOS release build requested but signing env vars are missing:
    ${missing[*]}

A signed + notarized build is required so end-users don't hit the
"Apple could not verify Sidevers" Gatekeeper warning. Set the four
APPLE_* env vars before running this, or — for local dev only —
override with:

    UNSIGNED=1 $0 build $*

One-time setup (cert generation, app-specific password, Team ID
lookup) is documented in docs/RELEASING.md → "macOS code signing".
EOF
        exit 1
    fi
    echo "==> macOS signing creds present: identity=\"$APPLE_SIGNING_IDENTITY\", team=$APPLE_TEAM_ID"
fi

cd "$TAURI_DIR"

echo "==> cargo tauri $SUBCMD $*"
cargo tauri "$SUBCMD" "$@"
