# Geist + Geist Mono — local font bundling

The Tauri desktop client loads Geist locally (Phase 3.J) instead of via
CDN, so that (a) the production CSP can stay tight (no `style-src
https://fonts.googleapis.com`, no `font-src https://fonts.gstatic.com`),
and (b) the app renders fully offline.

If this directory is missing the `.woff2` files listed below, the CSS
`font-family` chain in `dist/style.css` falls through to system
sans-serif (`-apple-system`, `Segoe UI`, etc.) — the app still works
and looks reasonable, just without the brand typography.

## Files expected here

```
fonts/Geist-Regular.woff2
fonts/Geist-Medium.woff2
fonts/Geist-SemiBold.woff2
fonts/GeistMono-Regular.woff2
```

## Where to get them

Vercel publishes Geist under the SIL Open Font License, so it's safe
to redistribute alongside the binary:

- Latest release: https://github.com/vercel/geist-font/releases
- Inside the release zip, the `.woff2` files live under
  `geist-font/dist/woff2/` (or similar — names match the spec above).

## One-line fetch (when network is available)

```sh
# from desktop/tauri/dist/fonts/, with a release tag in $TAG:
TAG=1.4.0
for f in Geist-Regular Geist-Medium Geist-SemiBold GeistMono-Regular; do
  curl -L -o "$f.woff2" \
    "https://github.com/vercel/geist-font/releases/download/v$TAG/$f.woff2"
done
```

(Pin the tag — fetching `latest` would change the bundle content
hash each build.)

## Why not bundle them in the repo?

Repo stays text-only (no binary assets beyond the small brand icons).
A CI step or one-time developer setup runs the fetch above; release
artifacts that ship to users include the downloaded files.
