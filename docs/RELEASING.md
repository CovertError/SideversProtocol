# Releasing Sidevers

This is how a release gets cut. The CI workflow is `.github/workflows/release.yml`.

## TL;DR

```bash
# Bump versions in:
#   - crates/sidevers-cli/Cargo.toml
#   - crates/sidevers-node/Cargo.toml
#   - crates/sidevers-ffi/Cargo.toml
#   - desktop/tauri/Cargo.toml
#   - desktop/tauri/tauri.conf.json   ("version")

git tag -s v0.1.1 -m "v0.1.1"
git push origin v0.1.1
```

That triggers `release.yml`, which builds every platform, signs the desktop
bundles, generates `latest.json`, and creates a **draft** GitHub Release.
Review the draft, publish it, and existing installs auto-update on next
launch.

---

## One-time setup (do this BEFORE the first signed release)

### 1. Generate the signing keypair

Tauri's updater verifies every build with an Ed25519 signature. You generate
the keypair once and keep the private key secret — only the GitHub Actions
runner ever sees it.

```bash
# In any directory you trust. The .key file will hold the private key.
cargo tauri signer generate -w ~/.tauri/sidevers.key
```

You'll be prompted for a password. Use one. Both pieces are needed to sign.

The command prints the **public key** to stdout — copy it.

### 2. Paste the public key into `tauri.conf.json`

Open `desktop/tauri/tauri.conf.json` and replace the placeholder:

```jsonc
"plugins": {
  "updater": {
    "endpoints": [
      "https://github.com/CovertError/SideversProtocol/releases/latest/download/latest.json"
    ],
    "pubkey": "REPLACE_ME_WITH_OUTPUT_OF_cargo_tauri_signer_generate",
    //          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    //          replace this string with the pubkey you just generated
    "windows": { "installMode": "passive" }
  }
}
```

Commit this change. The pubkey is **not** secret — it's how the client
verifies signed updates.

### 3. Add the private key + password to GitHub Actions secrets

```bash
# From the repo root:
gh secret set TAURI_SIGNING_PRIVATE_KEY < ~/.tauri/sidevers.key
gh secret set TAURI_SIGNING_PRIVATE_KEY_PASSWORD   # paste when prompted
```

(Or do it in the GitHub UI: Settings → Secrets and variables → Actions.)

### 4. Back up the private key

If you lose it, you lose the ability to ship signed updates to existing
users. They'd need to manually download a new build (with a new pubkey
baked in) to start auto-updating again. Treat this like a CA root.

Recommended: encrypted backup in your password manager + a cold copy on a
hardware key.

---

## Every release

1. Bump versions (see the list at the top).
2. Update `CHANGELOG.md` (or whatever you keep).
3. `git tag -s vX.Y.Z -m "vX.Y.Z"` then `git push origin vX.Y.Z`.
4. Watch `release.yml` in GitHub Actions. ~15-25 min end-to-end.
5. **Review the draft Release.** Sanity-check that `latest.json` is
   attached and lists every platform. Sanity-check the bundle filenames.
6. Click **Publish release**.

That's it. The desktop client picks the update up on next launch (via
`check_for_updates`), users see a prompt, and `apply_pending_update`
restarts them on the new build.

### CLI / node binaries

The same workflow ships `sidevers-cli-{linux-x64,macos-universal,windows-x64}.tar.gz`
(or `.zip` on Windows) alongside the desktop bundles. Each has a sibling
`.sha256` for `sidevers self-update` (Phase 2) to verify against.

### Pre-releases

Tag with `-alpha`, `-beta`, or `-rc` (e.g. `v0.2.0-rc1`) and the Release
is marked pre-release automatically. The updater only resolves the latest
stable `latest` tag, so pre-releases don't trip the auto-updater for the
general install base.

---

## Verifying a build by hand

Anyone can verify a signed `.dmg`/`.AppImage`/`.msi` against the public key.
The signature is stored alongside the bundle as `<bundle>.sig`.

```bash
# pubkey lives in desktop/tauri/tauri.conf.json under plugins.updater.pubkey
cargo tauri signer verify \
  --pubkey-path desktop/tauri/tauri.conf.json::plugins.updater.pubkey \
  --signature Sidevers_0.1.1_universal.dmg.sig \
  Sidevers_0.1.1_universal.dmg
```

---

## What the updater plugin does

On `check_for_updates`:

1. Fetches `latest.json` from the configured endpoint.
2. Compares its `version` against the running app's version.
3. If newer, returns metadata to the frontend (version, release notes, date).

On `apply_pending_update`:

1. Downloads the signed bundle for the running platform.
2. **Verifies the Ed25519 signature** against the embedded pubkey.
3. Refuses to install on a signature mismatch.
4. Installs and restarts the app.

The signature check is the only thing standing between users and a
poisoned binary on a compromised release. Treat the private key
accordingly.

---

## See also

- `desktop/tauri/tauri.conf.json` — updater config + bundle definitions
- `desktop/tauri/src/main.rs` — `check_for_updates` and `apply_pending_update` Tauri commands
- `.github/workflows/release.yml` — the CI pipeline
- [Tauri updater plugin docs](https://v2.tauri.app/plugin/updater/)
