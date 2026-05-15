#!/usr/bin/env bash
#
# Build sidevers-ffi as an iOS xcframework that Swift packages can consume.
#
# Output: mobile/swift/Frameworks/SideversFFI.xcframework
#
# Requirements:
#   - macOS host with Xcode CLI tools (xcodebuild, lipo)
#   - rustup with the iOS targets installed (see below)
#
# Usage:
#   ./mobile/build-ios.sh [--release]

set -euo pipefail

PROFILE="release"
CARGO_FLAG="--release"
if [ "${1:-}" = "--debug" ]; then
    PROFILE="debug"
    CARGO_FLAG=""
fi

# Resolve repo root from this script's location.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

HEADER_SRC="$REPO_ROOT/crates/sidevers-ffi/include/sidevers.h"
HEADER_DST_DIR="$REPO_ROOT/mobile/swift/Sources/SideversFFI/include"
XCFW_OUT="$REPO_ROOT/mobile/swift/Frameworks/SideversFFI.xcframework"

# 1. Install the iOS targets if missing.
echo "==> Ensuring iOS Rust targets installed"
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios

# 2. Build the staticlib for each target.
echo "==> Building sidevers-ffi staticlib for each iOS target"
cargo build $CARGO_FLAG -p sidevers-ffi --target aarch64-apple-ios
cargo build $CARGO_FLAG -p sidevers-ffi --target aarch64-apple-ios-sim
cargo build $CARGO_FLAG -p sidevers-ffi --target x86_64-apple-ios

DEVICE_LIB="$REPO_ROOT/target/aarch64-apple-ios/$PROFILE/libsidevers.a"
SIM_ARM_LIB="$REPO_ROOT/target/aarch64-apple-ios-sim/$PROFILE/libsidevers.a"
SIM_X86_LIB="$REPO_ROOT/target/x86_64-apple-ios/$PROFILE/libsidevers.a"

# 3. Combine the two simulator slices into a single fat .a (lipo).
SIM_FAT_DIR="$REPO_ROOT/target/ios-sim-fat/$PROFILE"
mkdir -p "$SIM_FAT_DIR"
SIM_FAT_LIB="$SIM_FAT_DIR/libsidevers.a"
echo "==> Fusing simulator slices into $SIM_FAT_LIB"
lipo -create "$SIM_ARM_LIB" "$SIM_X86_LIB" -output "$SIM_FAT_LIB"

# 4. Sync the C header into the Swift package's module map directory.
mkdir -p "$HEADER_DST_DIR"
cp "$HEADER_SRC" "$HEADER_DST_DIR/sidevers.h"
cat > "$HEADER_DST_DIR/module.modulemap" <<'EOF'
module SideversFFI {
    header "sidevers.h"
    export *
}
EOF

# 5. Build the xcframework bundling device + simulator + headers.
rm -rf "$XCFW_OUT"
mkdir -p "$(dirname "$XCFW_OUT")"
echo "==> Building xcframework at $XCFW_OUT"
xcodebuild -create-xcframework \
    -library "$DEVICE_LIB" -headers "$HEADER_DST_DIR" \
    -library "$SIM_FAT_LIB" -headers "$HEADER_DST_DIR" \
    -output "$XCFW_OUT"

echo "==> Done: $XCFW_OUT"
echo "    Swift Package Manager: import the 'Sidevers' product from this directory."
