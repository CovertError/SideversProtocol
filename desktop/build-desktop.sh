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

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TAURI_DIR="$REPO_ROOT/desktop/tauri"

if ! command -v cargo-tauri &> /dev/null; then
    echo "==> Installing tauri-cli (^2)"
    cargo install tauri-cli --version "^2"
fi

cd "$TAURI_DIR"

# Default subcommand is `dev` so a bare invocation hot-runs the app.
SUBCMD="${1:-dev}"
shift || true

echo "==> cargo tauri $SUBCMD $*"
cargo tauri "$SUBCMD" "$@"
