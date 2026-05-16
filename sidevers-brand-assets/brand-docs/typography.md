# Sidevers Typography

> *"Geist for the work. Instrument Serif for the soul."*
> — Sidevers Project Document v.2, §7.6

Two typefaces only. No third face. No alternates.

## Geist — primary

[Geist](https://vercel.com/font) by Vercel. Open-source, geometric sans-serif designed for screen reading and code. Used for headlines, body, interface chrome, and the wordmark.

**Why Geist for Sidevers:**

- Free and open-source — no licensing complications.
- Designed for digital interfaces — the medium Sidevers lives in.
- Geometric, restrained, technically literate — fits the project's voice.
- Pairs cleanly with serifs for accent moments.

### Geist usage

- **Headlines:** Geist Medium (500) or Semibold (600), tight tracking.
- **Body:** Geist Regular (400), default tracking.
- **Emphasis in body:** prefer Medium (500) over italic.
- **Captions/Labels:** Geist Regular (400) in Silver (#86868B).
- **Code:** Geist Mono — included in the Geist family.

**Never below weight 400.** Light, Thin, and ExtraLight weights are not in the Sidevers system.

### Fallback stack

```css
font-family: Geist, "Inter", "Helvetica Neue", Arial, sans-serif;
```

```css
font-family: "Geist Mono", "SF Mono", "Roboto Mono", Menlo, Consolas, monospace;
```

## Instrument Serif — accent

[Instrument Serif](https://fonts.google.com/specimen/Instrument+Serif) by Rodrigo Fuenzalida. Open-source italic serif designed for editorial use.

**Italic only.** One moment per page — a tagline, a pull quote, a chapter opener. Never for body. Never for buttons. Never for UI chrome. Its job is to feel, not to inform.

The brand's italic moments — *"Your actual life, on the internet."*, *"That point is you."* — are Instrument Serif. Used right, it's the one soft surface in an otherwise direct visual system.

## Type scale

Modular scale of 1.25, anchored at 16px body.

| Use | Size | Line height | Weight | Tracking |
|---|---|---|---|---|
| Display | 64px | 1.05 | 500 | -2% |
| Headline 1 | 48px | 1.1 | 500 | -1.5% |
| Headline 2 | 36px | 1.15 | 500 | -1% |
| Headline 3 | 28px | 1.2 | 500 | -0.5% |
| Subhead | 22px | 1.3 | 500 | 0 |
| Body large | 20px | 1.5 | 400 | 0 |
| Body | 16px | 1.5 | 400 | 0 |
| Caption | 14px | 1.5 | 400 | 0 |
| Small | 12px | 1.4 | 400 | 0 |

## Color and type

- **Body text:** Ink (#1D1D1F) on Snow (#FFFFFF) or Mist (#F5F5F7).
- **Secondary text** (captions, metadata, helper text): Silver (#86868B). Meets WCAG AA but intentionally softer.
- **Dark mode:** Mist (#F5F5F7) on Ink/Onyx.

Never use color on text outside the gray palette. No blue links, no green success messages, no red errors. Status is communicated by icon, weight, and surface treatment, not by color.

## The wordmark

"sidevers" — lowercase, Geist Medium (500), letter-spacing -0.05em (-5 units at 100px). Per Project Document §7.5: *Mark to the left, sized to roughly cap-height plus a touch of clearance.*

The SVG wordmark uses live text, depending on Geist being available to the rendering system. For production deployment:

1. Install Geist on your build systems (or load via CSS @font-face).
2. Convert the wordmark SVG's text to outlined paths so it renders font-independently. Any vector editor (Figma, Illustrator, Inkscape) does this with "Outline Stroke" / "Convert to Path."

— Sidevers Typography
