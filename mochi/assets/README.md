# Mochi brand assets

The Mochi mark is a *kagami-mochi* (鏡餅), the two-tier New Year rice cake and a nod
to Mochi's sibling CLI, `kagami`. Two flat, glossy rice-cake tiers sit on red-edged
*shihōbeni* paper on a hinoki *sanbō* stand. The Hyperledger Iroha sakura and its
leaves crown the stack where the traditional bitter orange sits, and the SORA 天 mark
is the stand's crest.

| File | Use |
| --- | --- |
| `mochi-mark.svg` | Primary mark on light or dark backgrounds. |
| `mochi-logo.svg` | Horizontal lockup with the rounded `mochi` wordmark; the i-dot is SORA red. |
| `mochi-icon.svg` | Application icon: the mark under a SORA sky with *kasumi* cloud bands. |
| `mochi-mascot.svg` | Face-less rice cake, leaves and sakura: the animated mascot layer. |
| `mochi-stand.svg` | Paper, stand and SORA crest: the static mascot layer. |
| `mochi-icon-512.png` | Window and dock icon embedded by `mochi-ui`. |
| `mochi-mascot-512.png`, `mochi-stand-512.png` | Mascot layers embedded by `mochi-ui`. |

Both source marks keep their original geometry and colors: the Iroha sakura
(`#BB0000` with its white line figure, from the Iroha documentation icon) and the SORA
mark (`#E3242D`). Mochi's own colors are rice white `#FFFFFF` to `#E3E8F1`, ink
`#2E2230`, hinoki `#EDCB8E`, leaf `#5BA85A`, sakura pink `#CF356D` and sky `#5B8DEF`.

The PNG files are renders of the SVG sources. After changing an SVG, render the PNGs
at 512 × 512 with any SVG renderer, for example:

```sh
rsvg-convert -w 512 -h 512 mochi/assets/mochi-icon.svg -o mochi/assets/mochi-icon-512.png
rsvg-convert -w 512 -h 512 mochi/assets/mochi-mascot.svg -o mochi/assets/mochi-mascot-512.png
rsvg-convert -w 512 -h 512 mochi/assets/mochi-stand.svg -o mochi/assets/mochi-stand-512.png
```

The desktop paints the face in `mochi-ui-egui/src/gui/brand.rs` using the same 512-unit
coordinates as `mochi-mark.svg`; keep the two in step when the face changes.
