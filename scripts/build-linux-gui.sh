#!/usr/bin/env bash
#
# Build the Sidevers desktop GUI for Linux x86_64 inside an Ubuntu 22.04
# Docker container. Output:
#   desktop/tauri/target/x86_64-unknown-linux-gnu/release/bundle/
# (deb, AppImage, rpm)
#
# Runs against the host repo as a bind mount so artefacts land back in
# the working tree.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="ubuntu:22.04"

docker run --rm \
  --platform linux/amd64 \
  -v "$REPO_ROOT":/work \
  -w /work \
  -e CARGO_HOME=/work/docker-cargo-cache/cargo \
  -e RUSTUP_HOME=/work/docker-cargo-cache/rustup \
  -e CARGO_TARGET_DIR=/work/docker-cargo-cache/target \
  "$IMAGE" \
  bash -ec '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends \
      build-essential ca-certificates curl pkg-config file \
      libwebkit2gtk-4.1-dev libgtk-3-dev libsoup-3.0-dev \
      librsvg2-dev libayatana-appindicator3-dev patchelf

    if [ ! -x "$CARGO_HOME/bin/cargo" ]; then
      curl --proto =https --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --default-toolchain stable --profile minimal
    fi
    export PATH="$CARGO_HOME/bin:$PATH"

    if [ ! -x "$CARGO_HOME/bin/cargo-tauri" ]; then
      cargo install tauri-cli --version "^2" --locked
    fi

    cd desktop/tauri
    cargo tauri build --bundles deb,appimage,rpm

    echo
    echo "=== bundle output ==="
    find target/release/bundle -maxdepth 3 -type f -name "*.deb" -o -name "*.AppImage" -o -name "*.rpm" 2>/dev/null
  '
