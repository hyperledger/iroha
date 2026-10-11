---
title: Petal Stream Transport
---

Petal Stream is the animated optical transport of Iroha. A sender shows a sequence of square
frames; a phone camera reads them; a payload (for KAGEMUSHA, an `IPM1` peer message of up to
about 10 KB) is reassembled on the other side. It is the "Sakura-storm" alternative to a stream
of QR codes: it needs no standard QR scanner, but it is built so that a plain camera of an old
phone can read it.

This document is normative for the wire format, the frame geometry and the receiver rules. The
reference implementation is the Rust crate `crates/iroha_petal`; the golden vectors in
`fixtures/petal/` are the cross-SDK conformance suite (§10). Where prose and code disagree, the
code and the fixtures win and this document is wrong.

## 1. Overview

A frame is a black square carrying four kinds of marks. Three of them carry data, one locates
the code:

| Mark | What it is | Role |
| --- | --- | --- |
| **Sakura finders** | Four solid five-petal blossoms in the canvas corners | Locate the code in a camera frame and give the perspective; any three suffice when a thumb, a glare or the frame edge hides one. |
| **天 tile field** | 256 tiles in a `天`-shaped mask of a 20×20 lattice | Each tile's **light/dark polarity** is one bit (lane `P`); the **katakana glyph** drawn in it is four bits (lane `K`). The mask is mirror-symmetric left/right and not top/bottom, so it also tells a decoder which way is up. |
| **Three dotted rings** | 80, 92 and 104 dot slots at radii 360, 410 and 460 | Which slots are lit carries 240 bits (lane `D`). Fixed *gates* at 3, 6 and 9 o'clock (none at 12) are always lit. |

Each lane is exactly one Reed–Solomon codeword over GF(256), so the lanes fail independently:

* lane `D` (big isolated dots) is the most robust and survives defocus that would defeat any QR code;
* lane `P` (tile polarity) is next;
* lane `K` (the katakana) is the high-rate "turbo" lane: it needs a reasonably sharp camera (blur up to about σ 1.5 px at 720p).

Every lane carries fountain-coded payload atoms, so **any one readable lane is useful by itself**
and the stream completes from whatever mixture of lanes and frames the camera manages to read.
Lost, torn or blended frames cost time, never correctness.

Petal Stream replaces the retired binary-grid prototype (`PS1` over `QrStreamFrame` bytes). It
does not carry `QrStreamFrame` or `IRQR` frames: it is a complete transport with its own framing,
forward error correction and payload integrity check. KAGEMUSHA payloads use the `kind` byte of
§5.4 with the same values as `IrohaPeerWireKindV1`, which are the KAGEMUSHA wallet V1 envelope
message tags (1 Offer, 2 Request, 3 Payment, 4 Credited, 5 SessionControl, 6 PolicyData,
7 Lineage; [wallet wire record](kagemusha_wallet_wire_v1.md) §3.4), and carry the encoded `IPM1` message as
the payload. Envelopes are at most 10,000 bytes, which the measurements in §8 use; Petal carries
any such message whole (§5.5: the default receiver limit is 65 536 bytes).

## 2. Frame geometry (normative)

All coordinates are *design units* on a square canvas of 1024 units, origin at the top-left, `y`
growing downward. A renderer scales the canvas to any pixel size (recommended at least 512 px; 768–1080 px
on phones). Angles are measured from the positive `x` axis and grow clockwise on the screen.

### 2.1 Palette

| Name | RGB |
| --- | --- |
| background | `(0, 0, 0)` |
| light (tile fill, finders) | `(250, 235, 244)` |
| pink (dots, glyphs on dark tiles) | `(245, 175, 208)` |
| ink (glyphs on light tiles) | `(20, 4, 14)` |

Decoders assume these luminance relations: ink ≈ 0.04 and pink ≈ 0.83 of the light fill. Do not
re-theme frames that are meant to be scanned.

### 2.2 Finders

Centres, clockwise from the top-left: `(72, 72)`, `(952, 72)`, `(952, 952)`, `(72, 952)`.
A finder is the union of a centre disc of radius 12 and five petal discs of radius 26 whose
centres lie 34 units from the finder centre at angles `-90° + 72°·k` (`k = 0..4`, the first petal points up),
drawn in the light colour. A notch of radius 6 centred 60 units from the finder centre along each
petal axis is cut out of the petal tips. The notches are cosmetic: a decoder may only rely on the
finder being one large, isolated, roughly round blob of diameter 120 units. Keep every other bright
object at least one finder diameter away from the finders (hide status bars and similar UI).

### 2.3 Tiles and the `天` mask

The lattice has 20 columns and 20 rows; cell `(col, row)` spans
`[222 + 29·col, 222 + 29·(col+1))` horizontally and likewise vertically. A tile is a 25×25 square
(corner radius 3) centred in its cell, leaving a 4-unit gutter. The glyph box is a 23×23 square
centred in the tile. The data tiles are the `#` cells of this mask, listed row 0 (top) first:

```
....############....
...##############...
..################..
.##################.
###..............###
###..............###
#########..#########
#########..#########
###..............###
###..............###
########....########
########....########
#######......#######
#######..##..#######
######..####..######
#####...####...#####
.###...######...###.
..###.########.###..
......########......
.....##########.....
```

There are exactly 256 data tiles, numbered `0..255` in row-major order of the `#` cells.

A **light** tile is drawn as the tile square filled with the light colour and the glyph in ink. A
**dark** tile has no fill (it is the black background) and the glyph is drawn in pink.

### 2.4 Katakana glyphs

Lane `K` uses sixteen katakana, a subset of the Iroha ordering chosen for mutual distinguishability
under blur. Symbol `0` is the first: **イ ロ ハ ニ ヘ ト ワ カ レ ム ノ ケ ア ヒ ス ン**.

Each glyph is a set of stroke polylines on a 32×32 grid (`y` down), drawn with round caps and joins
and a stroke width of 6.5 grid units, scaled into the 23-unit glyph box. The polylines and the derived
8×8 coverage templates that decoders match against are in `fixtures/petal/petal_stream_v1.json`
(`glyphs.strokes`, `glyphs.templates`) and are generated from `crates/iroha_petal/src/glyphs.rs`.
The template bytes are the matching contract; the polylines are the rendering contract.

### 2.5 Rings, gates and guards

Ring `r ∈ {0, 1, 2}` has radius `360, 410, 460` and `N_r = 80, 92, 104` slots; slot `k` is centred at
angle `2π·k / N_r`, so slot 0 is at 3 o'clock, slot `N_r/4` at 6 o'clock, slot `N_r/2` at 9 o'clock.
A lit slot is a pink dot of radius 11.

Three gates are always lit, with these dot counts for rings `(0, 1, 2)`:

| Gate | Base slot `b` | Dots on rings 0, 1, 2 |
| --- | --- | --- |
| right (3 o'clock) | `0` | 1, 1, 3 |
| bottom (6 o'clock) | `N_r/4` | 2, 2, 2 |
| left (9 o'clock) | `N_r/2` | 1, 2, 2 |

One dot occupies slot `b`; two dots occupy `b, b+1`; three dots occupy `b-1, b, b+1` (indices modulo
`N_r`). The slot on either side of a gate group is a *guard* and is always dark. There is no gate at
12 o'clock. The 16 gate dots, 18 guards and the remaining 242 slots partition the 276 slots; the
first 240 remaining slots in flat order (ring 0 slots ascending, then ring 1, then ring 2) are the
**data slots**, numbered `0..239`; the last two remaining slots are spare and dark.

## 3. Lanes (normative)

### 3.1 Cells to bytes

* **Lane `P`**, 32 bytes: bit `t` is `1` iff tile `t` is light. Byte `j` holds tiles `8j … 8j+7`, most
  significant bit first.
* **Lane `K`**, 128 bytes: tile `t` holds glyph symbol `g_t ∈ 0..15`. Byte `j` is `(g_{2j} << 4) | g_{2j+1}`.
* **Lane `D`**, 30 bytes: bit `b` is `1` iff data slot `b` is lit. Byte `j` holds bits `8j … 8j+7`, MSB first.

### 3.2 Codewords

The transmitted bytes of a lane are `RS(data ‖ parity) XOR whitening`.

| Lane | Codeword | Data | Parity | Corrects |
| --- | --- | --- | --- | --- |
| `P` | 32 B | 19 B | 13 B | 6 wrong bytes, or 13 erased |
| `K` | 128 B | 83 B | 45 B | 22 wrong bytes, or 45 erased |
| `D` | 30 B | 19 B | 11 B | 5 wrong bytes, or 11 erased |

**Reed–Solomon.** GF(256) with primitive polynomial `x⁸+x⁴+x³+x²+1` (`0x11D`), `α = 2`. The generator is
`∏_{i=0}^{nsym-1}(x − αⁱ)` (first root `α⁰`), the code is systematic with the data bytes first and the
highest-degree coefficient first (the same field and conventions as QR Code). Decoders must support
errors and erasures (`2·errors + erasures ≤ nsym`) and must verify that the corrected word has zero
syndromes before accepting it.

**Whitening.** A fixed pseudo-random byte string is XORed over the codeword so that every frame is
statistically balanced whatever the payload is. The generator is xorshift32 (`x ^= x << 13; x ^= x >> 17;
x ^= x << 5`, a zero seed becomes `0xDEADBEEF`); each output byte is the top byte (`x >> 24`) of the state
after an update. Seeds: `P = 0x50455441`, `K = 0x4B414E41`, `D = 0x444F5453`. The first
`word length` bytes of the sequence are used; the sequences are in the fixture.

## 4. Atoms and the fountain code (normative)

A payload of `len` bytes (1 ≤ `len` ≤ 2²⁴−1) is cut into `K = ⌈len / 16⌉` **source atoms** of 16 bytes
(the last zero padded). The code is a rateless random linear code over GF(2). Encoded atom `id`
(`u32`):

* `id < K`: source atom `id` (systematic);
* otherwise the XOR of the source atoms selected by a pseudo-random mask:

  ```
  mix32(x): x ^= x >> 16; x *= 0x85EBCA6B; x ^= x >> 13; x *= 0xC2B2AE35; x ^= x >> 16   (u32)
  seed     = mix32((id * 0x9E3779B1) ^ crc ^ 0xA5A5A5A5)
  word[w]  = mix32(seed + (w + 1) * 0x9E3779B9)            (all arithmetic modulo 2³²)
  ```

  Mask bit `j` is bit `j mod 32` of `word[⌊j/32⌋]`; bits `≥ K` are cleared; an all-zero mask is
  replaced by the single bit `id mod K`. `crc` is the payload CRC-32C (§5.1). The mixer must not be
  replaced by a GF(2)-linear generator such as xorshift: all masks would then lie in a subspace of
  dimension ≤ 32 and the code could never complete for `K > 32`.

A receiver recovers the payload by Gaussian elimination over GF(2) once it holds `K` linearly
independent atoms; about `K + 2` random atoms suffice. Verification is by the payload CRC-32C.

## 5. Stream layer (normative)

### 5.1 Identity

`crc` is CRC-32C (Castagnoli, reflected, init and final xor `0xFFFFFFFF`) of the payload. The one-byte
`tag` is `crc & 0xFF`. `kind` is an application byte (0 = unspecified).

### 5.2 Frames and atom ids

Frames carry a 16-bit counter `f` (wrapping). Frame `f` carries atoms in this order: lane `P` one atom, lane `D` one
atom (omitted on beacon frames, which are those with `f mod 4 = 0`), lane `K` five atoms. Atom ids are contiguous over the atoms
actually sent: the first atom of frame `f` has id `7·f − ⌈f / 4⌉`. (65536 is divisible by 4, so ids repeat
cleanly when the counter wraps.)

### 5.3 Lane data layouts (big-endian)

Every lane starts with a 3-byte header `tag:u8, frame:u16`. Then:

* lane `P`: one atom (16 B) → 19 B;
* lane `K`: five atoms (80 B) → 83 B;
* lane `D`, non-beacon frame: one atom → 19 B;
* lane `D`, beacon frame (`f mod 4 = 0`): `version:u8 (=0x10), kind:u8, len:u24, crc:u32` followed by 7 zero bytes → 19 B.

`version` = `0x10` means format version 1, layout profile 0; anything else is rejected.

### 5.4 Sender

Send frames `f = f₀, f₀+1, …` at 6–12 frames per second (8 is the default). The sender repeats until the
user stops it; the first `⌈K/6.75⌉` frames carry every source atom once and the rest are repair atoms. There is no
back-channel; if the receiver needs an acknowledgement it uses its own stream.

### 5.5 Receiver (assembler)

* A beacon locks the receiver to a stream `(kind, len, crc)`; lane headers carry only the tag. A
  different beacon replaces the active stream only after two consecutive sightings.
* Atoms that arrive before the first beacon are buffered (bounded, default 128) and replayed once
  the stream is known; atoms whose tag differs from the active stream are ignored.
* Beacons with `len = 0` or above the receiver's limit (default 65 536 bytes) are ignored. Memory and
  work are bounded by that limit (`K ≤ 4096` at the default).
* When the payload is solved its CRC-32C must match the beacon; if it does not, the elimination state
  is discarded and counted as an integrity failure while the stream continues.
* Only lane `D` carries the beacon, so a receiver needs to read lane `D` of at least one beacon frame to start; atoms read
  earlier are buffered, not lost. In every simulated condition lane `D` was the most robust lane.
* A completed stream is delivered exactly once; further frames of the same stream are ignored.
* Sessions forget a partial stream after an idle timeout (default 30 s) or an absolute timeout (default 180 s).

## 6. Rendering

Any 2D API may draw a frame as long as geometry, polarity and colours match §2. The reference software
renderer (`render.rs`) shades each sample in this order: finders, tiles (rounded tile square, then the glyph
bitmap), ring dots, background, with 2×2 or 3×3 supersampling. SDKs additionally expose a platform-neutral
*draw list* (finders, tiles with glyph index and polarity, glyph polylines, lit dots) so a native canvas can
play a stream without per-pixel work.

Display guidance: full screen brightness, a black surround, the whole square visible, no overlays within
one finder diameter of the finders, animation at 8 fps. Do not exceed one third of the camera frame rate:
frames shown for less than three camera frames are frequently blended or torn and are lost.

## 7. Decoding

A conforming decoder takes an 8-bit luma plane (the Y plane of an NV21/YUV camera frame, or luminance
computed as `(299R + 587G + 114B + 500) / 1000`) and must: locate the four finders, find the pose, resolve
orientation (four rotations, optionally mirrored), read the lanes and Reed–Solomon-decode them. It must never
report a lane whose Reed–Solomon check failed, and it must reject garbage (noise, blank frames) without crashing.

The reference algorithm, which the golden captures are calibrated to:

1. **Finders.** Adaptive threshold against the local mean (integral image; window radius `clamp(short side / 8, 12, 64)`).
   With `range = max(P99.5 − P2, 8)` over the luma percentiles, a pixel is lit when it exceeds the local mean by
   `max(s·range, 5)` and also exceeds `P2 + 0.2·range`, for sensitivities `s = 0.12, 0.22, 0.34`.
   Label 4-connected components. A finder candidate is a component with `size ≥ 14 px` (larger bounding-box side), area ≥ 100,
   fill (area / bounding box) 0.45–0.90 and principal-axis ratio ≥ 0.5, with no *other component of substance* (area ≥ 8 and
   at least 1.5 % of the candidate's area) whose centroid lies within 0.8 × its size. The *large* candidates are those of at
   least 0.55 × the largest; any set of candidates is ordered by size, largest first (ties in discovery order), and at most the
   first ten are combined. A *quad* is a combination of four that forms a convex quadrilateral with similar sizes
   (largest/smallest ≤ 1.9, longest/shortest side ≤ 2.6, mean side / mean size between 4.8 and 10.5); the one with the lowest
   score `(size ratio − 1) + (side ratio − 1) + |mean side / mean size − 7.33| / 7.33` wins. A *corner* is three candidates with
   sizes within 1.9, one of them (the vertex) with two legs whose lengths are within a factor 2, whose angle has
   `|cos| ≤ 0.5`, and whose mean length is 4.8–10.5 mean sizes; the lowest
   `(size ratio − 1) + (leg ratio − 1) + |cos| + |mean leg / mean size − 7.33| / 7.33` wins, and its fourth corner is the
   parallelogram point `a + c − vertex`. Finder centres are refined with an intensity-weighted centroid inside the blob
   (inferred corners are not).

   The decoder tries **candidate finder sets** in this order and keeps the first under which a lane decodes:
   1. for each sensitivity in turn, the quad of the large candidates;
   2. from the first sensitivity that has one, the corner of the large candidates completed by the nearest candidate of at least
      0.3 × the mean size within 0.3 mean legs of its parallelogram point (steep tilt makes the far finder small);
   3. from the first sensitivity that has one, the quad of all candidates;
   4. the corner of step 2 with its fourth finder **inferred** — hidden by a thumb, a glare or the edge of the frame.

   Only the sensitivities that are needed are computed: a clean frame costs one binarisation.
2. **Pose.** Homography from the four finder centres to the canonical corners, for each of 4 rotations (and 4 mirrored).
   An inferred corner is first moved to where the three dotted rings line up best: the brightness summed over all 276 ring
   slots (five-point samples as in step 4) is maximised over a 13 × 13 grid in steps of 2 % of the mean leg around the
   parallelogram point, then over a 9 × 9 grid in steps of 0.5 % around the best point. The ring slots map onto themselves under
   every quarter turn and mirror (80, 92 and 104 are multiples of four), so this search fixes the geometry once for all
   orientations; the orientation is decided in step 3. Reference levels come from the finders (lit, nine samples of the solid
   core) and the black canvas 100 units inward of them (dark); a corner whose lit level is less than 12 above its dark level
   refuses the candidate. An inferred corner has no levels of its own: its lit and dark levels are the parallelogram
   extrapolation of the other three, clamped to their range, and must differ by 12 as well (uneven light can push the two
   estimates past each other).
3. **Orientation.** Each hypothesis gets a *gate score* — the mean normalised sample of the gate dots minus that of the
   guards — and a *`天` score*: the mean normalised level of the 256 tiles (five-point samples spread ±8 units, so a glyph
   stroke at the centre does not decide it) minus the mean over the 144 lattice cells outside the mask. The rings tell
   rotations apart only through the gates, which glare or the frame edge can hide; the `天` is symmetric left to right but
   not top to bottom, so it tells the four quarter turns apart by itself (the lanes then settle a mirror). Hypotheses are
   ranked by gate score + `天` score. Try lane `D` under the best three whose gate score is at least 0.2; otherwise try the
   tile lanes (step 5) under the best four and accept the first hypothesis under which lane `P` or lane `K` decodes. The
   decoded frame reports the inferred corner, if any, as its canonical index (0 top-left, 1 top-right, 2 bottom-right,
   3 bottom-left of the upright code).
4. **Dots.** Sample each data slot (the mean of five points, the centre and four at ±3.5 units), normalise with the local
   lit/dark levels, and threshold per ring at the midpoint of that ring's gate and guard samples when they are more than 0.2
   apart (0.5 otherwise).
5. **Tiles.** For each tile sample an 8×8 patch over the glyph box (each cell is the mean of four bilinear samples at ±¼ cell)
   in luma levels. Two readings of the patches are defined; each picks, for every tile, the best of 32 hypotheses (polarity ×
   glyph) by sum of squared error against templates blurred with σ ∈ {0, 0.5, 0.8, 1.1, 1.5} template cells (the σ with the
   lowest total error wins):
   * *Level read.* Normalise every cell as `(v − dark) / (lit − dark)` with the lit/dark levels interpolated bilinearly between
     the four finders, and compare with the templates as drawn (ink 0.04, pink 0.83 of the light fill).
   * *Normalised read.* Used only for a lane that the level read could not decode. Rescale every patch so that its own 10th
     percentile (index 6 of the 64 sorted cells) becomes 0 and its 90th percentile (index 57) becomes 1, with a span of at least
     1 level, clamped to [−0.25, 1.25]; rescale every template the same way (span at least 0.001). The finder levels are not used,
     so over-exposure, veiling light, glare, shadows and gradients cancel. A tile whose span is below 0.25 × the median span of
     all 256 tiles is unreadable: its confidence is zero, which makes it the first erasure.

   Words for lanes `P` and `K` come from the level read; any lane that does not decode is retried with the words of the
   normalised read.
6. **Reed–Solomon with erasures.** Rank bytes by confidence, least confident first, with ties in position order (a stable sort:
   the weak tiles of step 5 all have confidence 0), and retry with 0, ⅛, ¼, ⅓ and ½ of the parity bytes as erasures (integer
   division: lane `D` 0, 1, 2, 3, 5; lane `P` 0, 1, 3, 4, 6; lane `K` 0, 5, 11, 15, 22), and for lane `K` only also ⅔ (30).
   Lanes `D` and `P` stop at ½: with 11 and 13 parity bytes, a further erasure step leaves so few spare ones that it lets wrong
   codewords through (§11).

**Tracking.** A scan session that decoded a frame reads the next ones by following that pose instead of searching the
whole image, as long as the pose is at most 500 ms old. Each corner finder is re-found from where the previous pose puts it:
an intensity-weighted centroid over a disc of twice the finder's expected diameter (nothing else bright is that close to a
corner finder), then centroids over the finder's own disc, at most five, until the centre moves less than ¼ px; a finder
with less than 20 levels of contrast in its disc, or ending more than 0.75 diameters from where it was expected, is lost.
The mean movement of the corners that were followed predicts the others. A corner inferred in the previous frame is seen
again only when its blossom is re-found within ¼ diameter of that prediction (a bright thumb beside it must not count).
With one corner missing, it is placed at the prediction and refined against the rings as in step 2; with two missing, or
when no lane decodes, the frame goes through the full search. The orientation is kept. Tracking takes about a quarter of the time of a full decode (§8).

The constants above are what the ports use; they may be tuned together with the fixtures. Decoding is not bit-reproducible
across platforms (it uses the platform's `sin`, `cos`, `exp` and `atan2`, and `f32` slot centres): conformance means the
golden captures decode to the recorded lanes, never that two platforms produce identical floating-point intermediates.

## 8. Qualification

All numbers below are from the camera simulator in `crates/iroha_petal/src/sim.rs`
(perspective and rotation, lens distortion, area integration, defocus blur, bloom, auto-exposure clipping,
ambient light and gradients, vignetting, sensor noise, sharpening, 8-bit quantisation, frame blending and tearing).
They are evidence from a model, **not** device measurements. Pixels per tile are given for the code filling about
80 % of the short side; a modern phone at 1080p is about 22 px/tile, a 720p preview about 15, a 480p preview about 9.

Per-frame decode rates (60 random poses per row, rotation 0–360°, tilt up to 12° unless stated):

| Condition | Any lane | `P` | `K` | `D` |
| --- | --- | --- | --- | --- |
| modern 720p, σ 0.7 px | 100 % | 100 % | 100 % | 100 % |
| legacy 720p, σ 1.3 px, noise 6, tilt 12°, barrel distortion | 100 % | 100 % | 100 % | 100 % |
| 720p blur σ 1.0 / 1.4 / 1.8 / 2.2 px | 100 % | 100 % | 100 / 100 / 53 / 0 % | 100 % |
| 720p defocus σ 2.6 / 3.2 / 4.0 px | 100 % | 100 % | 0 % | 100 % |
| 720p noise 13 levels | 100 % | 100 % | 100 % | 100 % |
| 720p tilt ≤ 25° / 35° / 45° | 100 / 100 / 92 % | same | 100 / 98 / 88 % | same |
| 480p, 6.7–9.1 px/tile, σ 1.2 px | 100 % | 100 % | 0 % | 100 % |
| 480p, 9.7–9.8 px/tile, σ 1.2 px | 100 % | 100 % | 37–40 % | 100 % |
| 480p defocus σ 2.6 / 3.2 px | 100 % | 100 / 68 % | 0 % | 100 % |
| harshest preset (480p, σ 1.7, tilt, bloom, ambient 10 %, barrel) | 100 % | 97 % | 0 % | 100 % |

Light, motion and framing that are not nominal (`stress` example, 40 poses per cell; each cell lists a modern 720p / a
legacy 720p / the harshest 480p camera; light levels are fractions of the lit level; hand shake is a linear blur of the given
length):

| Condition | Any lane | `P` | `K` | `D` |
| --- | --- | --- | --- | --- |
| veiling light 0.35 / 0.5 | 100 / 100 / 100 % | 100 / 100 / 0 % | 100 / 98–100 / 0 % | 100 / 100 / 100 % |
| auto-exposure gain 1.5× / 2× too high | 100 / 100 / 100 % | 100 / 98–100 / 0 % | 100 / 78–100 / 0 % | 100 / 100 / 100 % |
| auto-exposure gain 3× too high | 100 / 100 / 100 % | 100 / 12 / 0 % | 100 / 0 / 0 % | 100 / 100 / 100 % |
| illumination gradient equal to the lit level | 100 / 100 / 52 % | 100 / 100 / 0 % | 100 / 90 / 0 % | 100 / 100 / 52 % |
| glare 0.5 × lit, σ 120 px | 100 / 100 / 88 % | 100 / 98 / 2 % | 100 / 100 / 0 % | 98 / 98 / 88 % |
| glare 1.0 × lit, σ 120 px | 100 / 82 / 10 % | 100 / 60 / 0 % | 100 / 60 / 0 % | 72 / 60 / 10 % |
| banding (display PWM) 30 % deep, 30 px period | 100 / 100 / 100 % | 100 / 100 / 10 % | 100 / 98 / 0 % | 100 / 100 / 100 % |
| banding 50 % deep, 80 px period | 100 / 98 / 28 % | 20 / 2 / 0 % | 8 / 0 / 0 % | 100 / 98 / 28 % |
| hand shake 4 px | 100 / 100 / 100 % | 100 / 100 / 85 % | 60 / 12 / 0 % | 100 / 100 / 100 % |
| hand shake 9 px | 100 / 100 / 100 % | 100 / 100 / 30 % | 0 / 0 / 0 % | 100 / 100 / 100 % |
| a thumb over one corner blossom | 100 / 100 / 62 % | 100 / 100 / 42 % | 100 / 95 / 0 % | 100 / 100 / 62 % |
| a glare spot on one corner blossom | 95 / 98 / 85 % | 95 / 98 / 85 % | 95 / 5 / 0 % | 95 / 98 / 85 % |
| one corner outside the frame | 100 / 100 / 72 % | 100 / 100 / 70 % | 98 / 95 / 0 % | 100 / 100 / 72 % |

The tile lanes survive the lighting problems that old cameras actually have because of the normalised read of §7 step 5:
without it the same legacy camera loses `P` at 2× over-exposure (4 % of frames) and `K` at 1.5× (0 %). A hidden corner
blossom used to cost every lane; with the inferred corner of §7 steps 1–2 a thumb, a glare spot or a frame edge over one
blossom costs nothing at 720p (before: 0 % with a thumb, 0–2 % with a corner outside the frame). With all three ring gate
groups glared out, ranking by the `天` (§7 step 3) still reads 100 % of frames, against 95–98 % with the gates alone. Three
limits remain. A 480p preview reads only lane `D` as soon as the light is not nominal (its tiles are 9 px wide and blurred
into each other): that is why `D` is designed to work alone. A deep glare or wide, deep banding defeats every lane in the
frames it covers: that is why the stream is rateless and frames are shown for several camera frames. Hand shake costs lane
`K` first (it is gone at 9 px of blur) while `P` and `D` hold at 720p.

End to end (`stream_sim`: 8 fps animation, 30 fps camera, 1/60 s exposure with blending/tearing, random pose, 8 trials per
camera, received through a scan session that tracks the pose) for the largest KAGEMUSHA message, 10 000 bytes: **11.5 s**
with a modern or legacy camera (lane `K` readable in 95–96 % of frames), **16.5 s** on average with a soft 720p camera
(σ 1.8 px, lane `K` in 47 % of frames, 22 s at the 90th percentile) and **45 s** when only lanes `P` and `D` are readable
(480p). A 2 KB payload takes 2.2 s, 3.2 s and 9–12 s respectively. With the camera 2× over-exposed or under veiling light
of 0.35 a legacy camera still completes as fast as in nominal light; without the normalised read of §7 step 5 a 7 552-byte
payload needed 72 s and 32 s instead of 8.6 s. Completion was 100 % and no wrong payload was ever delivered.

Decode cost: at 1280×720 the reference decoder needs about 7.5 ms for a full search and 2 ms to track the pose of the
previous frame; a frame whose corner blossom is hidden costs about 21 ms the first time (all three thresholds, the corner
search) and is then tracked. A 7.5 KB stream through a tracking session averages 2.6–4.8 ms per camera frame, against
7–12 ms without tracking. Ports are expected to stay within a factor of 20 of the reference.

What this does and does not establish: it shows the format and decoder degrade gracefully — the lane that fails first is the
katakana lane, then polarity, then the dots — and that localisation does not depend on the content. It does not replace
physical qualification on the approved device list (autofocus behaviour, rolling shutter, OLED PWM flicker,
screen glare and real ISP sharpening are only modelled). The device protocol is: show the stream at 8 fps at maximum brightness, hold the
phone 20–30 cm away, record time-to-complete over 20 runs per device and distance, and file the lane statistics from `ScanStats`.

Scanner guidance that follows from the lighting rows: a phone camera left on automatic exposure over-exposes a mostly black
screen, so a scanner should use exposure compensation of about −1 EV (−2 EV on old cameras) where the camera API offers it, or lock
exposure once the finders are seen, and should discourage glare by asking the user to tilt the screen. The decoder tolerates
what is left over; it should not be asked to.

Run the evidence yourself:

```
cargo run --release -p iroha_petal --example qualify -- 60          # per-frame matrix
cargo run --release -p iroha_petal --example stress -- 40           # light, motion and hidden-corner matrix
cargo run --release -p iroha_petal --example stream_sim -- 8 10000 8 # end to end
iroha offline petal simulate --camera legacy --bytes 10000 --fps 8  # same, through the CLI
```

## 9. CLI

```
iroha offline petal encode   --input payload.bin --output out/ --kind 2 [--frames N] [--size 1024] [--fps 8] [--format png|gif]
iroha offline petal decode   --input-dir out/ --output payload.out
iroha offline petal inspect  --input out/frame_0000.png
iroha offline petal simulate --camera modern|legacy|soft|worst --bytes 10000 --fps 8 --trials 4
```

`encode` writes `frame_0000.png …` (or one looping `stream.gif` with the `offline-visual-codecs` feature) and
`manifest.json` (`iroha.offline.petal.encode.v1`). `decode` reads PNG frames in file-name order from a
directory — frames extracted from a screen recording work. `inspect` prints which lanes decode, the orientation and
the beacon of one frame.

## 10. Fixtures and conformance

* `fixtures/petal/petal_stream_v1.json` — constants, layout tables, glyph strokes and templates, CRC-32C, xorshift32/`mix32`,
  whitening, Reed–Solomon vectors, fountain masks, the atom-id schedule, and for three streams (`tiny`, `one-pass`, `wrap`) the
  lane data, transmitted words, glyph string and lit-dot list of every listed frame. Encoders must reproduce all of it bit for bit.
* `fixtures/petal/petal_captures_v1.json` — eleven degraded camera luma planes (zlib + base64, row-major 8-bit) with
  `must_decode` lanes, the lanes the reference decoder reads (`reference_decoded`), the expected lane data, a `mirrored` flag
  and the `inferred_corner` (null, or the canonical index of a hidden corner blossom); two tracking pairs (`tracks`: a first
  frame to decode and a second frame to read by tracking its pose, with `must_track`, `reference_tracked` and
  `inferred_corner`); and two negatives. A decoder must read the required lanes, must never return a lane with wrong data, must
  reject the negatives, and conforming ports reproduce `reference_decoded`, `reference_tracked` and the inferred corners
  exactly. Three captures exist for the normalised tile read of §7 (an over-exposed frame, veiling light, a shadow band), two for
  the inferred corner (a covered blossom, a corner outside the frame), and the tracking pairs cover a small hand movement and a
  thumb arriving over a blossom between two frames.
* Regenerate with `cargo run -p iroha_petal --example gen_fixtures -- fixtures/petal/petal_stream_v1.json` and
  `cargo run --release -p iroha_petal --example gen_captures -- fixtures/petal/petal_captures_v1.json`; `cargo test -p iroha_petal`
  fails if the files and the reference drift apart.

Implementations: Rust (`crates/iroha_petal`, `iroha offline petal`), Swift (`IrohaSwift`), Kotlin/Java (`kotlin/core-jvm`,
`kotlin/client-android`), JavaScript (`javascript/iroha_js`), Python (`python/iroha_petal`), C# (`csharp`).

## 11. Security considerations

* Frames are untrusted input. Decoders bound their work (`max_pixels` 12 MP, payload limit, bounded buffers) and never panic
  on malformed images; garbage fixtures are part of the suite.
* Reed–Solomon decoding with erasures can accept a word that is not a transmission: measured on uniformly random words, one
  decoding of a lane accepts 0.015 % of lane `D`, under 0.001 % of lane `P` and none of lane `K`. (Lane `D` used to try a
  seventh erasure and lane `P` an eighth; the first accepted 0.4 % of random words and cost five wrong lanes in 2 900 simulated
  harsh frames, the second two wrong lanes in 600 banded 480p frames. After the caps there were none, for 0.65 % fewer `D` and
  0.15 % fewer `P` lanes read.) The stream layer absorbs what is left: lane headers carry the stream
  tag (a stranger passes with probability 1/256) and the payload CRC-32C is verified before delivery, so a false accept costs at
  most an integrity reset, never a wrong payload.
* The payload CRC-32C and the Reed–Solomon codes detect corruption, not forgery. A screen in front of the camera can always show
  garbage or a different stream; the application must authenticate the payload (KAGEMUSHA messages carry their own proofs and
  signatures) and must not treat a completed Petal stream as authentic.
* A visible stream is readable by anyone who films it. Encrypt payloads that must stay private before streaming them.
* A stream that never completes (jamming) only wastes the user's time; sessions time out.

## 12. Open work

* TODO: physical-device qualification of the matrices in §8, including the OLED/PWM and rolling-shutter effects, and of the
  exposure-compensation guidance.
* TODO: a denser layout profile (the beacon `version` byte reserves the profile nibble) for cameras that resolve
  more than 22 px per tile. At 8 fps the present profile moves a 10,000-byte KAGEMUSHA message in about 11.5 s, far from
  the 2-second experience target of the single implementation draft; Petal is the carrier for cameras that cannot do
  better, not the fast path.
