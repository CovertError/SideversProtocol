# Sidevers 0.1.0 — Build Status

Built from `main` @ `16e11be` on macOS arm64 (Darwin 25.3.0) with
`rustc 1.95.0` and `zig 0.16.0`.

Mobile targets (iOS and Android) are intentionally not in this drop —
they need full app shells / store deployment that isn't ready yet. The
underlying `sidevers-ffi` library compiles cleanly for iOS and the
existing `mobile/build-ios.sh` / `mobile/build-android.sh` scripts will
produce framework artefacts when we want them. They are not in `dist/`.

All archive checksums are in [`SHA256SUMS`](SHA256SUMS).

## Per-target status

| Platform           | Artifact                                    | Status |
|--------------------|---------------------------------------------|--------|
| macOS universal    | `Sidevers.app` + `.dmg` + `.app.zip`        | OK     |
| macOS universal    | `bin/sidevers` (CLI)                        | OK     |
| macOS universal    | `bin/sidevers-node` (daemon)                | OK     |
| macOS universal    | `bin/sidevers-desktop` (raw Tauri binary)   | OK     |
| macOS universal    | `lib/libsidevers.{dylib,a}` + `sidevers.h`  | OK     |
| Linux x86_64       | `bin/sidevers`, `bin/sidevers-node`         | OK     |
| Linux x86_64       | `lib/libsidevers.{so,a}` + `sidevers.h`     | OK     |
| Linux x86_64       | `gui/Sidevers_0.1.0_amd64.deb` (Debian/Ubuntu/Mint) | OK |
| Linux x86_64       | `gui/Sidevers-0.1.0-1.x86_64.rpm` (Fedora/RHEL/openSUSE) | OK |
| Linux x86_64       | `gui/sidevers-desktop` (raw GUI binary)     | OK     |
| Linux aarch64      | `bin/sidevers`, `bin/sidevers-node`         | OK     |
| Linux aarch64      | `lib/libsidevers.{so,a}` + `sidevers.h`     | OK     |
| Windows x86_64     | `bin/sidevers.exe`, `bin/sidevers-node.exe` | OK     |
| Windows x86_64     | `lib/sidevers.dll`, `lib/libsidevers.a`     | OK     |
| Windows arm64      | —                                           | TODO   |
| Linux AppImage     | —                                           | TODO (needs privileged Docker for FUSE, or CI) |
| Windows desktop GUI| —                                           | TODO (use `.github/workflows/release.yml` on GitHub Actions) |
| iOS                | —                                           | Out of scope for this drop                |
| Android            | —                                           | Out of scope for this drop                |

## Distribution archives

- `sidevers-0.1.0-linux-x64.tar.gz`
- `sidevers-0.1.0-linux-arm64.tar.gz`
- `sidevers-0.1.0-windows-x64.zip`
- `macos-universal/Sidevers-0.1.0-universal.dmg`
- `macos-universal/Sidevers-0.1.0-universal.app.zip`

## How each was built

```bash
# macOS CLI + node + FFI (universal)
cargo build --release -p sidevers-cli -p sidevers-node -p sidevers-ffi \
    --target aarch64-apple-darwin --target x86_64-apple-darwin
lipo -create target/{aarch64,x86_64}-apple-darwin/release/sidevers      -output dist/macos-universal/bin/sidevers
lipo -create target/{aarch64,x86_64}-apple-darwin/release/sidevers-node -output dist/macos-universal/bin/sidevers-node
lipo -create target/{aarch64,x86_64}-apple-darwin/release/libsidevers.dylib -output dist/macos-universal/lib/libsidevers.dylib
lipo -create target/{aarch64,x86_64}-apple-darwin/release/libsidevers.a     -output dist/macos-universal/lib/libsidevers.a

# Desktop (Tauri) — universal .app + .dmg
desktop/build-desktop.sh build --target universal-apple-darwin
#   → desktop/tauri/target/universal-apple-darwin/release/bundle/macos/Sidevers.app
# Tauri's create-dmg wrapper requires Finder automation permissions; if it fails,
# wrap the .app with plain hdiutil:
#   hdiutil create -volname Sidevers -srcfolder <stage> -ov -format UDZO out.dmg

# Linux + Windows cross-compile (needs `brew install zig` + `cargo install cargo-zigbuild`)
cargo zigbuild --release -p sidevers-cli -p sidevers-node -p sidevers-ffi \
    --target x86_64-unknown-linux-gnu \
    --target aarch64-unknown-linux-gnu \
    --target x86_64-pc-windows-gnu

# Linux desktop GUI (.deb + .rpm) — needs Docker Desktop running
scripts/build-linux-gui.sh
```

## Deferred — Windows desktop GUI

Tauri's Windows bundler needs MSVC + the WebView2 SDK; cross-compiling
that stack from macOS is unreliable. The clean path is the matrix CI
build in `.github/workflows/release.yml` — trigger it from the GitHub
Actions tab and grab the `sidevers-windows-x64` artefact.

## Deferred — Linux / Windows desktop GUI

Tauri's webview is platform-supplied (WebKit2GTK on Linux, WebView2 on
Windows), so the desktop app has to be built on (or in a container for)
each target OS. From this macOS host we shipped the CLI + node + FFI for
both platforms; the GUI ships when we wire up Linux/Windows CI runners.

## Local smoke test

```bash
# macOS
./dist/macos-universal/bin/sidevers --version
open dist/macos-universal/Sidevers.app

# Linux / Windows
tar xzf dist/sidevers-0.1.0-linux-x64.tar.gz && ./linux-x64/bin/sidevers --help
unzip dist/sidevers-0.1.0-windows-x64.zip && ./windows-x64/bin/sidevers.exe --help
```

## Reproducing this build

```bash
rustup target add x86_64-apple-darwin aarch64-apple-darwin \
                  x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu \
                  x86_64-pc-windows-gnu
brew install zig                  # cross-linker for Linux + Windows
cargo install cargo-tauri --version "^2"
cargo install cargo-zigbuild
```
