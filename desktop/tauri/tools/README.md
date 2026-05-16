# Tailwind CSS v4 standalone binary

Tauri client UI overhaul (Phase 3 redesign) uses Tailwind v4 to
build `dist/style.css` from `dist/input.css`. Tailwind v4 ships
OS-native binaries — no Node.js / npm required.

The binary lives at `tools/tailwindcss` (gitignored — different
binary per OS, no need to vacuum the repo with 80 MB of native
executables).

## One-time setup

Pin to a known-good release tag (don't fetch `latest` — release
churn would change the bundled binary out from under us). The
build script verifies the binary is present and exits with a
clear error otherwise.

### macOS (Apple Silicon)

```sh
cd desktop/tauri
TAG=v4.0.0
curl -L -o tools/tailwindcss \
  "https://github.com/tailwindlabs/tailwindcss/releases/download/$TAG/tailwindcss-macos-arm64"
chmod +x tools/tailwindcss
tools/tailwindcss --help    # smoke test
```

### macOS (Intel)

```sh
TAG=v4.0.0
curl -L -o tools/tailwindcss \
  "https://github.com/tailwindlabs/tailwindcss/releases/download/$TAG/tailwindcss-macos-x64"
chmod +x tools/tailwindcss
```

### Linux

```sh
TAG=v4.0.0
ARCH=$(uname -m)
case "$ARCH" in
  x86_64) SUFFIX=linux-x64 ;;
  aarch64|arm64) SUFFIX=linux-arm64 ;;
  *) echo "unsupported arch $ARCH"; exit 1 ;;
esac
curl -L -o tools/tailwindcss \
  "https://github.com/tailwindlabs/tailwindcss/releases/download/$TAG/tailwindcss-$SUFFIX"
chmod +x tools/tailwindcss
```

### Windows

Download `tailwindcss-windows-x64.exe` from the same release
and save as `tools/tailwindcss.exe`.

## Running the build

Once the binary is in place, `desktop/tauri/build-tailwind.sh` is
the integration point:

```sh
cd desktop/tauri
bash build-tailwind.sh         # one-shot build
bash build-tailwind.sh --watch # rebuild on change (dev)
```

The Tauri `beforeDevCommand` / `beforeBuildCommand` invoke this
script automatically (see `tauri.conf.json`). If the binary is
missing the script exits non-zero with the URL to download from
— Tauri's build then fails fast with a clear error message
rather than running with stale CSS.

## Why pin the tag?

A floating `latest` would mean every developer + CI builds with
whatever Tailwind happened to publish that day. Reproducibility
matters for design regressions: if the same input.css produces
different output.css next week, debugging is much harder. Bump
the tag deliberately when you want a Tailwind upgrade.

## Why not commit the binary?

Multi-platform repos don't want 4× ~80 MB per-platform binaries
in tree. Per-developer download keeps the repo lean and the
download is one-time per OS install.

## Why not vendor Tailwind v4 source + build from npm?

We deliberately don't have a `package.json` anywhere in this
repo. Adding npm would mean adding lockfile + node_modules to the
build matrix and tightening the toolchain reproducibility story.
The standalone binary is the friction-minimizing path.
