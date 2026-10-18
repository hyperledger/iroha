# Mochi brand assets

The Mochi mark is a soft rice cake crowned with the Hyperledger Iroha sakura, like the
orange on a *kagami-mochi* (a nod to Mochi's sibling CLI, `kagami`), and stamped with
the SORA 天 seal the way a painter signs a work with a red *rakkan*.

| File | Use |
| --- | --- |
| `mochi-mark.svg` | Primary mark on light or dark backgrounds. |
| `mochi-logo.svg` | Horizontal lockup with the rounded `mochi` wordmark; the i-dot is SORA red. |
| `mochi-icon.svg` | Application icon: the mark on a SORA sky with a cloud bank. |
| `mochi-mascot.svg` | Face-less mark. The desktop paints the face so it can follow network state. |
| `mochi-icon-512.png` | Window and dock icon embedded by `mochi-ui`. |
| `mochi-mascot-512.png` | Mascot texture embedded by `mochi-ui`. |

Both source marks keep their original geometry and colors: the Iroha sakura
(`#BB0000` with its white line figure, from the Iroha documentation icon) and the SORA
seal (`#E3242D`). Mochi's own colors are rice cream `#FFF7EF`, ink `#2E2230`, sakura
pink `#CF356D` and sky `#5B8DEF`.

The PNG files are renders of the SVG sources. After changing an SVG, render the PNGs
at 512 × 512 with any SVG renderer, for example:

```sh
rsvg-convert -w 512 -h 512 mochi/assets/mochi-icon.svg -o mochi/assets/mochi-icon-512.png
rsvg-convert -w 512 -h 512 mochi/assets/mochi-mascot.svg -o mochi/assets/mochi-mascot-512.png
```

The desktop face is drawn in `mochi-ui-egui/src/gui/brand.rs` using the same 512-unit
coordinates as `mochi-mark.svg`; keep the two in step when the face changes.
