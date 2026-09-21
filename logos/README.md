# Postern — logo pack

A large gate and a small lit one beside it. The big arch is the bank's main way in; the small amber gate is Postern — narrower, deliberate, and the one that's open.

## Files

**Lockup** (mark + wordmark)

| File | Use on |
|---|---|
| `svg/postern-lockup-light.svg` | Light backgrounds — the default |
| `svg/postern-lockup-dark.svg` | Dark backgrounds, transparent |
| `svg/postern-lockup-badge.svg` | Anywhere; carries its own navy background |
| `svg/postern-lockup-mono-black.svg` / `-mono-white.svg` | Single-colour print, embossing, fax, anywhere colour isn't available |

**Mark only**

| File | Use |
|---|---|
| `svg/postern-mark-light.svg` / `-dark.svg` | The mark alone, 32px and above |
| `svg/postern-mark-mono-black.svg` | Single-colour |
| `svg/postern-icon-compact-light.svg` / `-dark.svg` | **Below 32px.** Enlarged side gate so it survives small sizes |

**Icons**

| File | Use |
|---|---|
| `svg/postern-app-icon.svg`, `png/avatar-512.png` | GitHub org, Slack app, Confluence space, avatars |
| `png/apple-touch-icon-180.png` | iOS home screen |
| `svg/postern-favicon.svg`, `png/favicon.ico`, `png/favicon-{16,32,48}.png` | Browser tabs |
| `png/postern-lockup-*@2x.png` | Slides and docs where SVG isn't accepted |

## Colours

| | Hex | Role |
|---|---|---|
| Navy | `#1F2A44` | Ink on light, background for badge and icons |
| Amber | `#C8752B` | The small gate, on light |
| Cream | `#F4F1EA` | Ink on dark |
| Amber (on dark) | `#E39A52` | The small gate, on dark |

## Rules

1. **Amber is only ever the small gate.** It means "the way in." Don't use it for text, backgrounds, or decoration elsewhere in the identity.
2. **Don't recolour the gates independently**, swap their sizes, or reorder them. The small gate is always on the right and always smaller.
3. **Below 32px, use the compact icon.** The standard mark's side gate becomes a dot at favicon sizes.
4. **Minimum lockup height: 20px.** Below that, use the icon alone.
5. **Clear space:** keep at least the height of the small gate free on every side.
6. **Mono versions** exist for when colour isn't available. Don't approximate the colour versions in greyscale — use mono.

## Typeface

The wordmark is set in **Inter Display Medium** at −0.01em tracking, with kerning applied, then converted to outlines. The files don't depend on the font being installed.

Inter is licensed under the SIL Open Font License 1.1 (© The Inter Project Authors, github.com/rsms/inter). Use Inter Display for any headings that need to sit alongside the logo.

## Favicon snippet

```html
<link rel="icon" href="/postern-favicon.svg" type="image/svg+xml">
<link rel="icon" href="/favicon.ico" sizes="16x16 32x32 48x48">
<link rel="apple-touch-icon" href="/apple-touch-icon-180.png">
```
