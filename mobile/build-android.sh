#!/usr/bin/env bash
#
# Build the Sidevers JNI bridge as Android .so libraries laid out for
# inclusion in an AAR's jniLibs/ directory.
#
# Output: mobile/android/kotlin/src/main/jniLibs/{abi}/libsidevers_jni.so
#
# Requirements:
#   - Linux or macOS host
#   - rustup with Android targets installed (script does this)
#   - Android NDK (set ANDROID_NDK_HOME or ANDROID_NDK_ROOT)
#   - cargo-ndk (the script installs it if missing; needs `cargo install cargo-ndk`)
#
# Usage:
#   ./mobile/build-android.sh [--debug]

set -euo pipefail

PROFILE="release"
CARGO_NDK_FLAGS="--release"
if [ "${1:-}" = "--debug" ]; then
    PROFILE="debug"
    CARGO_NDK_FLAGS=""
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

NDK_HOME="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"
if [ -z "$NDK_HOME" ]; then
    echo "ERROR: ANDROID_NDK_HOME or ANDROID_NDK_ROOT must be set" >&2
    exit 1
fi
export ANDROID_NDK_HOME="$NDK_HOME"

JNI_OUT="$REPO_ROOT/mobile/android/kotlin/src/main/jniLibs"
mkdir -p "$JNI_OUT"

# 1. Install the Android targets if missing.
echo "==> Ensuring Android Rust targets installed"
rustup target add aarch64-linux-android x86_64-linux-android armv7-linux-androideabi i686-linux-android

# 2. Install cargo-ndk if missing (handles toolchain wiring for us).
if ! command -v cargo-ndk &> /dev/null; then
    echo "==> Installing cargo-ndk"
    cargo install cargo-ndk
fi

# 3. Build the JNI bridge cdylib for each ABI.
echo "==> Building sidevers-jni for Android ABIs"
cargo ndk \
    -t aarch64-linux-android -t armv7-linux-androideabi \
    -t x86_64-linux-android -t i686-linux-android \
    -o "$JNI_OUT" \
    build -p sidevers-jni $CARGO_NDK_FLAGS

echo "==> Done. jniLibs layout:"
find "$JNI_OUT" -type f -name "*.so" | sort

echo
echo "    The Android module at mobile/android/kotlin/ can now be consumed"
echo "    as a Gradle module that bundles these .so files into its AAR."
