# Sidevers Brand Assets

Brand asset pack for Sidevers, derived from the canonical brand description in the Sidevers Project Document v.2, §7. **The mark and brand colors are trademarked and proprietary to Sidevers Inc.** Per the Licensing & Openness document, brand assets carry no license: no fork, no port, no derivative work may use the Sidevers name, mark, or visual system.

## The mark

> *"Two infinities, crossed. An infinity is two S's joined. Two infinities crossed are four sides held by one circle — public, private, work, close. Every loop passes through the same point. That point is you."*
> — Sidevers Project Document v.2, §7.2

The mark consists of:

- **The circle** — your universe; the place every side of you lives.
- **Two infinities** — four loops, woven through one point. Sidevers, sides, selves.
- **The center** — where every loop meets. You.

Two presentation modes:

- **Hero / app-icon:** silver mark on a black rounded-square. For app icons, splash screens, hero presentations. (`mark-hero.svg`, and built into `logo-horizontal.svg` and `logo-stacked.svg`.)
- **Flat:** single-color mark, no container. For small sizes, monochrome contexts, embroidery, single-color print. (`mark.svg` and color variants.)

## What's in this pack

### `svg/` — Source SVG files

**Mark, flat single-color variants:** `mark.svg` (Ink), `mark-black.svg`, `mark-white.svg`, `mark-silver.svg`

**Mark, hero / app-icon:** `mark-hero.svg`

**Wordmark** — lowercase "sidevers" in Geist Medium: `wordmark.svg`, plus black/white/silver variants

**Logo lockups (mark + wordmark):**
- `logo-horizontal.svg` — Hero mark + wordmark. The primary lockup.
- `logo-stacked.svg` — Hero mark above wordmark.
- `logo-horizontal-flat.svg` + color variants — Flat for monochrome contexts.
- `logo-stacked-flat.svg` + color variants

### `png/` — Pre-rendered PNGs

Flat mark, hero mark, wordmark, and both lockups at standard sizes (16 px through 2400 px) in all color variants. 79 files.

### `favicon/` — Web favicons

Generated from the hero mark. Includes `favicon.ico` (multi-res), individual PNGs from 16 to 512 px, `apple-touch-icon.png`, Android Chrome icons, and `site.webmanifest`.

Install on a website by copying to the site root and adding:

```html
<link rel="icon" type="image/x-icon" href="/favicon.ico">
<link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png">
<link rel="manifest" href="/site.webmanifest">
<meta name="theme-color" content="#000000">
```

### `brand-docs/` — Reference

- `colors.css` — CSS variables with dark-mode support
- `colors.json` — Machine-readable palette
- `swatches.svg` / `swatches.pdf` / `swatches.png` — Visual color reference
- `typography.md` — Geist + Instrument Serif system

## Brand palette

Six grays. Nothing else.

| Name | Hex | Role |
|---|---|---|
| Snow | `#FFFFFF` | Pure light |
| Mist | `#F5F5F7` | Soft surface — backgrounds |
| Silver Light | `#D2D2D7` | Border, divider |
| Silver | `#86868B` | Secondary text, captions |
| Ink | `#1D1D1F` | Primary text, headlines — the foreground |
| Onyx | `#000000` | Mark container, high contrast |

## Typography

**Geist** — primary. UI, body, headlines, the wordmark. Medium for emphasis, Regular for body. Never below 400 weight.

**Instrument Serif** — accent, italic only. One moment per page — a tagline, a pull quote. Never for body, never for buttons.

The wordmark is "sidevers" lowercase in Geist Medium, tracking -0.05em.

See `brand-docs/typography.md` for the full system.

## Usage rules

**The mark**

- Always preserve proportions. Don't squash, stretch, or recolor outside the palette.
- Hero variant is the canonical presentation at 64px and up.
- Below 64px the inner knot becomes a quiet texture; let the circle do the work.
- Clear space: at least 25% of the mark's height on all sides.

**The wordmark**

- Always lowercase. The sentence-starting "S" applies in prose, not in the wordmark itself.
- Geist Medium, tracking -0.05em.
- Minimum cap-height: 12px.

**The combined logo**

- Horizontal: headers, business cards, email signatures.
- Stacked: portrait orientations, splash screens.
- Don't recombine. Use the provided files.

**Color usage**

- On light: hero variant or flat ink (#1D1D1F).
- On dark: hero variant or flat white (#FFFFFF).
- For subdued contexts: flat silver (#86868B).

**What you cannot do**

- Don't apply additional gradients or effects beyond the hero variant's existing treatment.
- Don't rotate, mirror, or skew the mark.
- Don't put text inside the mark's circle.
- Don't use the mark in custom compositions.

## Notes

The hero variant approximates the chiseled-silver effect shown in the project doc using a linear gradient. A production rendering would use richer treatments. The flat variants are the working master for most practical uses.

Wordmark SVGs use live text. For production, convert to outlined paths (Figma: "Outline Stroke" / "Flatten") so they render font-independently. The PNGs were rendered with a fallback typeface since Geist isn't installed on the build system; re-rendering with Geist installed produces the proper glyphs.

For trademark filings: vector originals with text-as-paths, high-resolution PNGs at 600+ DPI, and a designer review of optical balance at all target sizes.

— Sidevers Brand Assets, v2
