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

There are **two independent signing systems** in play. Both need to be set
up before the first public release. Don't confuse them:

| System | What it signs | Why |
|---|---|---|
| **Apple Developer ID** | The macOS `.app` / `.dmg` bundles | Without it, every macOS user sees *"Apple could not verify Sidevers is free of malware…"* and the app refuses to open. |
| **Tauri updater key** | The bundle bytes themselves (Ed25519) | Lets the in-app auto-updater refuse a poisoned binary even if GitHub Releases is compromised. Independent of Apple. |

Sections 1–4 below cover the Tauri updater key. Section 5 covers Apple
Developer ID. Both are required for a clean macOS release.

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

### 5. macOS code signing (Apple Developer ID)

This is what makes `Sidevers.app` open on every Mac without the
*"Apple could not verify…"* Gatekeeper warning. You need an active
Apple Developer Program membership (you have one).

The flow:

```
CSR  ──►  Apple portal  ──►  .cer file  ──►  Keychain
                                                  │
                                                  ▼
                              codesign  ──►  notarytool  ──►  stapler
                              (Tauri does all three for you)
```

#### 5.1. Generate the Developer ID Application certificate

Apple won't ship you a cert directly — you generate a private key on
your Mac and send Apple a **Certificate Signing Request (CSR)** that
asks them to vouch for the matching public key.

1. Open **Keychain Access** on the Mac you'll build releases from.
2. Menu bar: **Keychain Access → Certificate Assistant → Request a
   Certificate From a Certificate Authority…**
3. Fill in:
   - **User Email Address**: your Apple Developer Program email
   - **Common Name**: `Omar @ Cyberagora` (or your dev name — this becomes part of the cert subject)
   - **CA Email Address**: leave blank
   - **Request is**: select **Saved to disk**
4. Click **Continue**, save the `CertificateSigningRequest.certSigningRequest` file somewhere you'll find it.
5. Go to <https://developer.apple.com/account/resources/certificates/list>.
6. Click the **+** to add a new certificate.
7. Under **Software**, select **Developer ID Application** → Continue.
   (Not "Developer ID Installer" — that's only for `.pkg` installers.)
8. Upload the `.certSigningRequest` file → Continue → Download.
9. Double-click the downloaded `developerID_application.cer` to install
   it into your **login** keychain.

Verify:

```bash
security find-identity -v -p codesigning
```

You should see a line like:

```
1) AB12CD34EF56… "Developer ID Application: Your Name (TEAMID1234)"
```

The quoted string — including `Developer ID Application:` and the
parenthesized Team ID — is your `APPLE_SIGNING_IDENTITY`.

#### 5.2. Generate an app-specific password for notarization

Apple's notary service won't accept your real Apple ID password — it
wants an app-specific password instead.

1. Go to <https://account.apple.com/account/manage>.
2. **Sign-In and Security → App-Specific Passwords**.
3. Click **Generate an app-specific password**.
4. Label it `Sidevers notary` (or whatever).
5. Copy the 19-character password (format `xxxx-xxxx-xxxx-xxxx`). Save
   it — Apple will not show it again.

This is your `APPLE_PASSWORD`.

#### 5.3. Find your Team ID

1. <https://developer.apple.com/account>.
2. **Membership Details** (or **Account → Membership**).
3. Copy the **Team ID** (10 characters, alphanumeric, e.g. `AB12CD34EF`).

This is your `APPLE_TEAM_ID`. It also appears in the parenthesized
part of `APPLE_SIGNING_IDENTITY`.

#### 5.4. Local environment: build a signed `.dmg` from your Mac

Add these to your shell profile (`~/.zshrc` or `~/.bashrc`), or
export them in the terminal before each build:

```bash
export APPLE_SIGNING_IDENTITY="Developer ID Application: Your Name (TEAMID1234)"
export APPLE_ID="omar@cyberagora.sa"
export APPLE_PASSWORD="xxxx-xxxx-xxxx-xxxx"
export APPLE_TEAM_ID="TEAMID1234"
```

Then:

```bash
./desktop/build-desktop.sh build --target universal-apple-darwin
```

The script verifies all four env vars are set, runs `cargo tauri
build`, and Tauri does the rest:

1. `codesign` against the Developer ID Application identity (using
   the entitlements at `desktop/tauri/macos/entitlements.plist`).
2. Submits the signed bundle to Apple's notary service via
   `notarytool` — this takes 1–5 minutes.
3. Staples the notary ticket back onto the `.app` so it works offline.

Output: `desktop/tauri/target/universal-apple-darwin/release/bundle/dmg/Sidevers_*.dmg`,
ready to ship.

Verify (optional but reassuring):

```bash
codesign -dv --verbose=4 path/to/Sidevers.app
# Look for: Authority=Developer ID Application: Your Name (TEAMID)
#           Authority=Developer ID Certification Authority
#           Authority=Apple Root CA
#           Sealed Resources version=2 rules=...
#           ...
# And:
spctl -a -t exec -vv path/to/Sidevers.app
# Should print: "accepted" "source=Notarized Developer ID"
```

#### 5.5. GitHub Actions: signed CI releases

For the CI pipeline to produce signed builds, the same creds — plus
your cert exported as a `.p12` — need to live in repo secrets.

**Export the cert as `.p12`:**

1. Open **Keychain Access** → **login** keychain → **My Certificates**.
2. Find `Developer ID Application: Your Name (TEAMID)`.
3. **Right-click → Export…** → choose **Personal Information Exchange (.p12)**.
4. Save somewhere private (e.g. `~/Documents/sidevers-codesign.p12`).
5. Set a strong password when prompted — this is your `APPLE_CERTIFICATE_PASSWORD`.

**Base64-encode and store in GitHub:**

```bash
# From the repo root:
base64 -i ~/Documents/sidevers-codesign.p12 | gh secret set APPLE_CERTIFICATE
gh secret set APPLE_CERTIFICATE_PASSWORD       # paste the .p12 password
gh secret set APPLE_SIGNING_IDENTITY            # paste the identity string
gh secret set APPLE_ID                          # your Apple ID email
gh secret set APPLE_PASSWORD                    # the app-specific password
gh secret set APPLE_TEAM_ID                     # 10-char Team ID
```

That's the full set: six macOS secrets, plus the two `TAURI_SIGNING_*`
ones from section 3 — eight GitHub secrets total for a signed release.

**Verify they're all there:**

```bash
gh secret list
# Should include all eight, no values shown.
```

#### 5.6. Back up the `.p12`

Treat it the same way you treat the Tauri updater key: encrypted
backup in your password manager + cold copy on a hardware key. If
you lose it, you can revoke and regenerate at developer.apple.com,
but every existing user's "Open Anyway" gesture (if any) is keyed to
the old cert's signature — they'd need to re-trust on first launch.

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

The same workflow ships `sidevers-cli-{linux-x64,linux-arm64,macos-universal,windows-x64}.tar.gz`
(or `.zip` on Windows) alongside the desktop bundles. Each has a sibling
`.sha256` that `sidevers self-update` consults via the asset metadata
GitHub serves over HTTPS.

#### `sidevers self-update`

CLI users (servers, hosted nodes, anyone who doesn't run a GUI) can
upgrade in place without leaving the shell:

```bash
sidevers self-update            # check + apply with prompt
sidevers self-update --yes      # check + apply, no prompt
sidevers self-update --check    # report only, don't install
sidevers self-update --version v0.1.2   # pin to a specific tag
```

The subcommand:

1. Looks up the running binary's compile-time target (`macos-universal` /
   `linux-x64` / `linux-arm64` / `windows-x64`).
2. Queries the configured GitHub Releases endpoint for the latest tag.
3. Compares versions with **semver semantics** (so a local dev build
   ahead of the latest published release is reported "ahead of latest"
   and **refuses to downgrade** unless `--version` is passed explicitly).
4. Downloads the matching `sidevers-cli-{target}.{tar.gz|zip}`.
5. Atomically replaces the running binary on disk and exits — the next
   invocation runs the new version.

Asset matching is constrained to filenames containing `sidevers-cli` so
the desktop bundles (`.dmg`, `.AppImage`, `.msi`, `.deb`, `.rpm`) on
the same release never confuse the CLI updater.

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
