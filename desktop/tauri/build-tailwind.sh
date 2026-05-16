#!/usr/bin/env bash
# desktop/tauri/build-tailwind.sh — Phase 3 UI redesign build script.
#
# Generates dist/style.css from dist/input.css using the standalone
# Tailwind v4 CLI binary at tools/tailwindcss. The binary is
# per-developer / per-OS download; see tools/README.md.
#
# Tauri's beforeBuildCommand / beforeDevCommand invoke this from
# desktop/tauri/. It's also runnable standalone:
#
#   bash build-tailwind.sh           # one-shot build (minified)
#   bash build-tailwind.sh --watch   # rebuild on change (dev mode)
#
# Exit codes:
#   0 — build OK
#   1 — binary missing (clear error + setup instructions emitted)
#   2 — Tailwind itself reported an error (output preserved as-is)

set -u
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Resolve the binary path. Tools dir has README + per-OS instructions.
BIN="tools/tailwindcss"
if [ ! -x "$BIN" ] && [ ! -x "$BIN.exe" ]; then
    cat <<'EOF' >&2
build-tailwind: tools/tailwindcss not found.

This is a one-time setup. The standalone Tailwind v4 CLI binary
is per-OS, gitignored, and lives at desktop/tauri/tools/tailwindcss.

Quick fetch (macOS, Apple Silicon):

    cd desktop/tauri
    TAG=v4.0.0
    curl -L -o tools/tailwindcss \
      "https://github.com/tailwindlabs/tailwindcss/releases/download/$TAG/tailwindcss-macos-arm64"
    chmod +x tools/tailwindcss

For other platforms see tools/README.md.

EOF
    exit 1
fi

# Pick the right binary name (Windows uses .exe).
if [ -x "$BIN.exe" ]; then
    BIN="$BIN.exe"
fi

INPUT="dist/input.css"
OUTPUT="dist/style.css"

if [ ! -f "$INPUT" ]; then
    echo "build-tailwind: missing $INPUT" >&2
    exit 1
fi

# Pass through --watch / --no-minify etc. Otherwise default to a
# minified one-shot build.
EXTRA_ARGS=("$@")
if [ ${#EXTRA_ARGS[@]} -eq 0 ]; then
    EXTRA_ARGS=(--minify)
fi

echo "build-tailwind: $BIN -i $INPUT -o $OUTPUT ${EXTRA_ARGS[*]}"
"$BIN" -i "$INPUT" -o "$OUTPUT" "${EXTRA_ARGS[@]}" || exit 2

# Quick sanity: confirm the file actually got written and isn't empty.
if [ ! -s "$OUTPUT" ]; then
    echo "build-tailwind: $OUTPUT is empty after build; aborting" >&2
    exit 2
fi

echo "build-tailwind: wrote $OUTPUT"
