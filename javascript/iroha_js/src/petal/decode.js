// From a camera luma plane to lane data.
//
// The decoder locates the four finders (or three, inferring the fourth),
// derives a homography for each orientation hypothesis, ranks the hypotheses
// by how well the ring gates and the `天` line up, then reads the tiles and
// dots. Every tile is classified jointly: the 8x8 sample patch is compared
// against the 32 hypotheses (polarity x glyph) and the best match wins, so the
// katakana and the light/dark bit help each other. Cells the decoder is unsure
// about become Reed-Solomon erasures. A scan session follows a code from one
// frame to the next by tracking its pose instead of searching again.
//
// The tile level read judges every patch against the light and dark levels
// measured at the finders. When it leaves lane P or K unreadable, the
// normalised read is tried: it rescales each patch (and each template) by its
// own contrast, so over-exposure, veiling light, glare, shadows and gradients
// cancel out.
//
// Every floating-point expression follows the reference operation by
// operation. Intermediates match the reference wherever the platform's sin,
// cos, exp and atan2 agree (they are not guaranteed to across platforms);
// conformance is that the golden captures decode to the recorded lanes.

import { PetalHomography, applyHomography, homographyFromPoints } from "./geometry.js";
import { GLYPH_COUNT, TEMPLATES, TEMPLATE_N } from "./glyphs.js";
import { sampleLuma } from "./image.js";
import { D_WORD, K_WORD, P_WORD, PetalFrameCells, decodeLaneCountedStatus, laneSpec } from "./lanes.js";
import {
  D_BITS,
  DATA_SLOT,
  FINDER_CENTERS,
  GATE_SLOT_LIST,
  GLYPH_BOX,
  GUARD_SLOT_LIST,
  MASK,
  RING_COUNT,
  SLOT_CENTER_X,
  SLOT_CENTER_Y,
  SLOT_RING,
  TILE_CENTER_X,
  TILE_CENTER_Y,
  TILE_COUNT,
  TILE_ORIGIN,
  TILE_PITCH,
  TOTAL_SLOTS,
} from "./layout.js";
import { finderCandidates, followFinder } from "./locate.js";
import { parseAtomLane, parseDLane } from "./stream.js";
import { PetalError, clamp, fmax, fmin, totalCmp } from "./support.js";

const PATCH = TEMPLATE_N;
const CELLS = PATCH * PATCH;
const HYPOTHESES = 2 * GLYPH_COUNT;
/** Relative level of the glyph ink on a light tile (ink / light fill). */
const INK_ON_LIGHT = 0.04;
/** Relative level of a pink glyph on a dark tile (pink / light fill). */
const PINK_ON_DARK = 0.83;
/** Cells cut from each end of a sorted patch to find its robust darkest and brightest level. */
const PATCH_CUT = Math.floor(CELLS / 10);
/** Smallest span, in luma levels, that counts as contrast when a camera patch is rescaled. */
const PATCH_SPAN_FLOOR = 1.0;
/** Smallest span that counts as contrast when a template is rescaled. */
const TEMPLATE_SPAN_FLOOR = 0.001;
/**
 * Tiles whose contrast is below this fraction of the median tile contrast become erasures
 * in the normalised read.
 */
const WEAK_TILE = 0.25;

/** Default decoder tuning. */
export const DEFAULT_DECODE_OPTIONS = Object.freeze({
  /** Also try horizontally mirrored images (front-camera previews). */
  tryMirrored: true,
  /** Blur widths (in template cells) tried for glyph matching. */
  templateSigmas: Object.freeze([0, 0.5, 0.8, 1.1, 1.5]),
  /**
   * Largest image (in pixels) the decoder accepts; larger frames should be
   * downscaled by the caller. Bounds memory and work on hostile input.
   */
  maxPixels: 12000000,
});

/** Validates and completes decoder options. */
export function resolveDecodeOptions(options) {
  if (options === undefined || options === null) {
    return DEFAULT_DECODE_OPTIONS;
  }
  if (typeof options !== "object") {
    throw new TypeError("decode options must be an object");
  }
  const tryMirrored = options.tryMirrored ?? DEFAULT_DECODE_OPTIONS.tryMirrored;
  const templateSigmas = options.templateSigmas ?? DEFAULT_DECODE_OPTIONS.templateSigmas;
  const maxPixels = options.maxPixels ?? DEFAULT_DECODE_OPTIONS.maxPixels;
  if (typeof tryMirrored !== "boolean") {
    throw new TypeError("tryMirrored must be a boolean");
  }
  if (
    !Array.isArray(templateSigmas) ||
    templateSigmas.length === 0 ||
    templateSigmas.some((sigma) => typeof sigma !== "number" || !Number.isFinite(sigma))
  ) {
    throw new TypeError("templateSigmas must be a non-empty array of finite numbers");
  }
  if (typeof maxPixels !== "number" || !(maxPixels >= 0)) {
    throw new TypeError("maxPixels must be a non-negative number");
  }
  return Object.freeze({ tryMirrored, templateSigmas: Object.freeze(templateSigmas.slice()), maxPixels });
}

// Unit vectors of the eight reference-level sample directions.
const REFERENCE_COS = new Float64Array(8);
const REFERENCE_SIN = new Float64Array(8);
for (let k = 0; k < 8; k += 1) {
  const angle = (2 * Math.PI * k) / 8;
  REFERENCE_COS[k] = Math.cos(angle);
  REFERENCE_SIN[k] = Math.sin(angle);
}

/** Maps canvas `(x, y)` through `m` and samples the image there. */
function sampleCanvas(image, m, x, y) {
  const w = m[6] * x + m[7] * y + m[8];
  const px = (m[0] * x + m[1] * y + m[2]) / w;
  const py = (m[3] * x + m[4] * y + m[5]) / w;
  return sampleLuma(image.data, image.width, image.height, px, py);
}

function dotSamples(image, m, x, y, spread) {
  let sum = 0;
  sum += sampleCanvas(image, m, x + 0, y + 0);
  sum += sampleCanvas(image, m, x + spread, y + 0);
  sum += sampleCanvas(image, m, x + -spread, y + 0);
  sum += sampleCanvas(image, m, x + 0, y + spread);
  sum += sampleCanvas(image, m, x + 0, y + -spread);
  return sum / 5;
}

/**
 * Light and dark levels at the four corners: the solid blossom core, and the black canvas 100
 * units inward of it (interpolated bilinearly over the canvas by the readers), or `null` when a
 * finder has too little contrast. An `inferred` corner (canonical index) was not seen, so its
 * levels are extrapolated from the other three by the parallelogram rule and kept within their
 * range, and must differ by 12 like a seen corner's. Exported for tests only.
 */
export function referenceLevels(image, m, inferred = null) {
  const lit = new Float64Array(4);
  const dark = new Float64Array(4);
  for (let i = 0; i < 4; i += 1) {
    if (inferred === i) {
      continue;
    }
    const cx = FINDER_CENTERS[i][0];
    const cy = FINDER_CENTERS[i][1];
    // the blossom is solid out to radius 24 around its centre
    let sum = sampleCanvas(image, m, cx, cy);
    for (let k = 0; k < 8; k += 1) {
      sum += sampleCanvas(image, m, cx + 20 * REFERENCE_COS[k], cy + 20 * REFERENCE_SIN[k]);
    }
    lit[i] = sum / 9;
    const sx = cx < 512 ? 1 : -1;
    const sy = cy < 512 ? 1 : -1;
    const a = dotSamples(image, m, cx + sx * 100, cy, 5);
    const b = dotSamples(image, m, cx, cy + sy * 100, 5);
    dark[i] = 0.5 * (a + b);
    // also refuses NaN levels, which only a non-finite pose can produce
    if (!Number.isFinite(lit[i] - dark[i]) || lit[i] - dark[i] < 12) {
      return null;
    }
  }
  if (inferred !== null) {
    const n1 = (inferred + 1) % 4;
    const opposite = (inferred + 2) % 4;
    const n2 = (inferred + 3) % 4;
    const extrapolate = (v) => {
      const low = fmin(fmin(v[n1], v[opposite]), v[n2]);
      const high = fmax(fmax(v[n1], v[opposite]), v[n2]);
      return clamp(v[n1] + v[n2] - v[opposite], low, high);
    };
    lit[inferred] = extrapolate(lit);
    dark[inferred] = extrapolate(dark);
    // uneven light can push the estimates past each other; an inferred corner
    // needs the same contrast as a seen one
    if (lit[inferred] - dark[inferred] < 12) {
      return null;
    }
  }
  return { lit, dark };
}

function mixCorners(c, u, v) {
  const top = c[0] * (1 - u) + c[1] * u;
  const bottom = c[3] * (1 - u) + c[2] * u;
  return top * (1 - v) + bottom * v;
}

function clampUnit(value) {
  return value < 0 ? 0 : value > 1 ? 1 : value;
}

/** `(x, y)` normalised with the light and dark levels interpolated there. */
function normalisedLevel(reference, sample, x, y) {
  const u = clampUnit(x / 1024);
  const v = clampUnit(y / 1024);
  const lit = mixCorners(reference.lit, u, v);
  const dark = mixCorners(reference.dark, u, v);
  return (sample - dark) / (lit - dark);
}

// Centres of the lattice cells outside the `天` mask (no tile is ever drawn there), row-major.
const EMPTY_X = [];
const EMPTY_Y = [];
MASK.forEach((line, row) => {
  for (let col = 0; col < line.length; col += 1) {
    if (line[col] !== "#") {
      EMPTY_X.push(TILE_ORIGIN + TILE_PITCH * (col + 0.5));
      EMPTY_Y.push(TILE_ORIGIN + TILE_PITCH * (row + 0.5));
    }
  }
});

/**
 * How well the `天` lines up: the mean normalised level over the tiles (each sampled at five
 * points across the tile, so a glyph stroke at the centre does not decide it) minus the mean
 * over the empty lattice cells. The mask is symmetric left to right but not top to bottom, so
 * this tells the four quarter turns apart even when the ring gates are damaged. Exported for
 * tests only.
 */
export function maskScore(image, m, reference) {
  let tiles = -0;
  for (let tile = 0; tile < TILE_COUNT; tile += 1) {
    const x = TILE_CENTER_X[tile];
    const y = TILE_CENTER_Y[tile];
    tiles += normalisedLevel(reference, dotSamples(image, m, x, y, 8), x, y);
  }
  let empty = -0;
  for (let cell = 0; cell < EMPTY_X.length; cell += 1) {
    const x = EMPTY_X[cell];
    const y = EMPTY_Y[cell];
    empty += normalisedLevel(reference, dotSamples(image, m, x, y, 8), x, y);
  }
  return tiles / TILE_COUNT - empty / EMPTY_X.length;
}

/**
 * Canonical index (0 top-left, 1 top-right, 2 bottom-right, 3 bottom-left of the upright code)
 * of the corner at index `index` of a finder quad under one orientation hypothesis.
 */
function canonicalCorner(index, rotation, mirrored) {
  return mirrored ? (rotation + 4 - index) % 4 : (index + 4 - rotation) % 4;
}

const CANONICAL_X = Float64Array.from(FINDER_CENTERS, (center) => center[0]);
const CANONICAL_Y = Float64Array.from(FINDER_CENTERS, (center) => center[1]);

/**
 * The brightness summed over all ring slots under the pose that maps the canonical corners onto
 * the quad `(xs[i], ys[i])`, or `null` when that pose is degenerate. The slots form the same set
 * of points under every quarter turn and mirror of the canvas (80, 92 and 104 are multiples of
 * four), so the value does not depend on the orientation.
 */
function ringBrightness(image, xs, ys) {
  const m = homographyFromPoints(CANONICAL_X, CANONICAL_Y, xs, ys);
  if (m === null) {
    return null;
  }
  let sum = -0;
  for (let flat = 0; flat < TOTAL_SLOTS; flat += 1) {
    sum += dotSamples(image, m, SLOT_CENTER_X[flat], SLOT_CENTER_Y[flat], 3.5);
  }
  return sum;
}

/**
 * Moves an inferred corner to where the three dotted rings line up best: a 13 x 13 search in
 * steps of 2 % of the mean leg around the parallelogram estimate, then a 9 x 9 search in steps
 * of 0.5 % around the best point. The rings fix the geometry only; the orientation is decided
 * afterwards by the gates and the `天`. Returns a new quad. Exported for tests only.
 */
export function refineInferredCorner(image, corners, inferred) {
  const xs = Float64Array.from(corners, (finder) => finder.x);
  const ys = Float64Array.from(corners, (finder) => finder.y);
  const startX = xs[inferred];
  const startY = ys[inferred];
  const distance = (other) =>
    Math.sqrt((xs[other] - startX) * (xs[other] - startX) + (ys[other] - startY) * (ys[other] - startY));
  const leg = 0.5 * (distance((inferred + 1) % 4) + distance((inferred + 3) % 4));
  let bestBrightness = -Number.MAX_VALUE;
  let bestX = startX;
  let bestY = startY;
  const search = (centreX, centreY, step, reach) => {
    for (let dy = -reach; dy <= reach; dy += 1) {
      for (let dx = -reach; dx <= reach; dx += 1) {
        const x = centreX + dx * step;
        const y = centreY + dy * step;
        xs[inferred] = x;
        ys[inferred] = y;
        const brightness = ringBrightness(image, xs, ys);
        if (brightness !== null && brightness > bestBrightness) {
          bestBrightness = brightness;
          bestX = x;
          bestY = y;
        }
      }
    }
  };
  search(startX, startY, 0.02 * leg, 6);
  search(bestX, bestY, 0.005 * leg, 4);
  const refined = corners.slice();
  refined[inferred] = { x: bestX, y: bestY, size: corners[inferred].size };
  return refined;
}

function normalisedDot(image, m, reference, flat) {
  const x = SLOT_CENTER_X[flat];
  const y = SLOT_CENTER_Y[flat];
  const u = clampUnit(x / 1024);
  const v = clampUnit(y / 1024);
  const lit = mixCorners(reference.lit, u, v);
  const dark = mixCorners(reference.dark, u, v);
  return (dotSamples(image, m, x, y, 3.5) - dark) / (lit - dark);
}

function gateScore(image, m, reference) {
  let gates = -0;
  for (const slot of GATE_SLOT_LIST) gates += normalisedDot(image, m, reference, slot);
  let guards = -0;
  for (const slot of GUARD_SLOT_LIST) guards += normalisedDot(image, m, reference, slot);
  return gates / GATE_SLOT_LIST.length - guards / GUARD_SLOT_LIST.length;
}

/** Reads lane D: returns the transmitted bytes and per-byte confidence. */
function readDots(image, m, reference) {
  // per-ring thresholds from the gates (lit) and guards (dark)
  const thresholds = [0.5, 0.5, 0.5];
  for (let ring = 0; ring < RING_COUNT; ring += 1) {
    let litSum = -0;
    let litCount = 0;
    for (const slot of GATE_SLOT_LIST) {
      if (SLOT_RING[slot] !== ring) continue;
      litSum += normalisedDot(image, m, reference, slot);
      litCount += 1;
    }
    let darkSum = -0;
    let darkCount = 0;
    for (const slot of GUARD_SLOT_LIST) {
      if (SLOT_RING[slot] !== ring) continue;
      darkSum += normalisedDot(image, m, reference, slot);
      darkCount += 1;
    }
    if (litCount > 0 && darkCount > 0) {
      const l = litSum / litCount;
      const d = darkSum / darkCount;
      if (l - d > 0.2) {
        thresholds[ring] = 0.5 * (l + d);
      }
    }
  }
  const word = new Uint8Array(D_WORD);
  const confidence = new Float64Array(D_WORD).fill(Number.MAX_VALUE);
  for (let bit = 0; bit < D_BITS; bit += 1) {
    const slot = DATA_SLOT[bit];
    const value = normalisedDot(image, m, reference, slot);
    const threshold = thresholds[SLOT_RING[slot]];
    if (value > threshold) {
      word[bit >> 3] |= 1 << (7 - (bit & 7));
    }
    confidence[bit >> 3] = fmin(confidence[bit >> 3], Math.abs(value - threshold));
  }
  return { word, confidence };
}

/** Lane D under one pose. */
function readLaneD(image, m, reference) {
  const dots = readDots(image, m, reference);
  return decodeWithErasures("D", dots.word, dots.confidence);
}

/**
 * Tries Reed-Solomon with growing numbers of erasures, least confident first.
 *
 * The schedule erases 0, 1/8, 1/4, 1/3 and 1/2 of the parity bytes (integer
 * division), and for lane K also 2/3: lane D 0, 1, 2, 3, 5; lane P 0, 1, 3, 4,
 * 6; lane K 0, 5, 11, 15, 22, 30. Lanes D and P stop at 1/2: their words have
 * only 11 and 13 parity bytes, and a further erasure step leaves so few spare
 * ones that it accepts wrong codewords (lane D at 7 erasures: about 0.4 % of
 * random words, and 5 wrong lanes in 2 900 simulated harsh frames; lane P at 8:
 * 2 wrong lanes in 600 banded 480p frames, in the reference's simulation).
 * Capping them costs 0.65 % of the lane D reads and 0.15 % of the lane P reads
 * in those frames.
 *
 * Returns `{data, corrected, erasures}`: `corrected` is the number of byte
 * positions the decoder rewrote (the erased bytes plus any errors it found
 * among the others, a measure of how close the lane was to failing) and
 * `erasures` the number of bytes passed as erasures. Exported for tests only.
 */
export function decodeWithErasures(lane, word, confidence) {
  const spec = laneSpec(lane);
  const nsym = spec.parityLen;
  // The ranking must be stable: byte-valued confidences tie a lot, and the tie order decides
  // which bytes are erased.
  const order = [];
  for (let index = 0; index < word.length; index += 1) order.push(index);
  order.sort((a, b) => totalCmp(confidence[a], confidence[b]));
  const steps = [0, Math.floor(nsym / 8), Math.floor(nsym / 4), Math.floor(nsym / 3), Math.floor(nsym / 2)];
  if (spec.name === "K") {
    steps.push(Math.floor((nsym * 2) / 3));
  }
  // consecutive duplicates are dropped, as with the reference's `dedup`
  const schedule = [];
  for (const erasures of steps) {
    if (schedule.length === 0 || schedule[schedule.length - 1] !== erasures) {
      schedule.push(erasures);
    }
  }
  for (const erasures of schedule) {
    const positions = order.slice(0, erasures);
    const trial = Uint8Array.from(word);
    // zero the erased bytes so stale values cannot leak through
    for (const position of positions) trial[position] = 0;
    const result = decodeLaneCountedStatus(spec, trial, positions);
    if (typeof result !== "number") {
      return Object.freeze({ data: result.data, corrected: result.corrected, erasures: positions.length });
    }
  }
  return null;
}

const patternCache = new Map();
const rescaledPatternCache = new Map();

/** `pred[h * 64 + cell]`: expected normalised patch for hypothesis `h = polarity * 16 + glyph`. */
function buildPatterns(sigma) {
  const raw = new Float64Array(5);
  for (let i = -2; i <= 2; i += 1) {
    raw[i + 2] = sigma < 0.05 ? (i === 0 ? 1 : 0) : Math.exp(-(i * i) / (2 * sigma * sigma));
  }
  let total = -0;
  for (const value of raw) total += value;
  const kernel = raw.map((value) => value / total);
  const pred = new Float64Array(HYPOTHESES * CELLS);
  const coverage = new Float64Array(CELLS);
  for (let polarity = 0; polarity < 2; polarity += 1) {
    for (let glyph = 0; glyph < GLYPH_COUNT; glyph += 1) {
      const template = TEMPLATES[glyph];
      for (let cell = 0; cell < CELLS; cell += 1) coverage[cell] = template[cell] / 255;
      const base = (polarity * GLYPH_COUNT + glyph) * CELLS;
      for (let v = 0; v < PATCH; v += 1) {
        for (let u = 0; u < PATCH; u += 1) {
          let acc = 0;
          for (let ky = 0; ky < 5; ky += 1) {
            const sy = v + ky - 2;
            for (let kx = 0; kx < 5; kx += 1) {
              const sx = u + kx - 2;
              if (sx >= 0 && sx < PATCH && sy >= 0 && sy < PATCH) {
                acc += kernel[kx] * kernel[ky] * coverage[sy * PATCH + sx];
              }
            }
          }
          pred[base + v * PATCH + u] = polarity === 1 ? 1 - (1 - INK_ON_LIGHT) * acc : PINK_ON_DARK * acc;
        }
      }
    }
  }
  return pred;
}

/**
 * The templates of one blur width, cached per width. With `rescaled` every template is
 * rescaled by its own contrast like the patches of the normalised read.
 */
function patternsFor(sigma, rescaled) {
  const cache = rescaled ? rescaledPatternCache : patternCache;
  const cached = cache.get(sigma);
  if (cached !== undefined) {
    return cached;
  }
  let pred;
  if (rescaled) {
    const plain = patternsFor(sigma, false);
    pred = new Float64Array(plain.length);
    for (let hypothesis = 0; hypothesis < HYPOTHESES; hypothesis += 1) {
      rescale(plain, hypothesis * CELLS, TEMPLATE_SPAN_FLOOR, pred);
    }
  } else {
    pred = buildPatterns(sigma);
  }
  if (cache.size >= 16) {
    cache.clear();
  }
  cache.set(sigma, pred);
  return pred;
}

function newReads() {
  return {
    light: new Uint8Array(TILE_COUNT),
    glyph: new Uint8Array(TILE_COUNT),
    polarityMargin: new Float64Array(TILE_COUNT),
    glyphMargin: new Float64Array(TILE_COUNT),
    error: new Float64Array(TILE_COUNT),
    count: 0,
  };
}

const PATCHES = new Float64Array(TILE_COUNT * CELLS);
const WORK = new Float64Array(TILE_COUNT * CELLS);
const SORTED = new Float64Array(CELLS);
const SPANS = new Float64Array(TILE_COUNT);
const SPANS_SORTED = new Float64Array(TILE_COUNT);
const ERASED = new Uint8Array(TILE_COUNT);
const ERRORS = new Float64Array(HYPOTHESES);
const PATCH_OFFSETS = Float64Array.of(-0.25, -0.25, 0.25, -0.25, -0.25, 0.25, 0.25, 0.25);

/**
 * The raw 8x8 luma patch of every tile, as captured (no reference levels applied): each of the
 * 64 cells is the mean of four bilinear samples at +-1/4 cell. Writes `256 * 64` values, tile by
 * tile and row by row, into `out` (allocated when omitted) and returns it. Exported for tests
 * only.
 */
export function samplePatches(image, m, out = new Float64Array(TILE_COUNT * CELLS)) {
  const half = GLYPH_BOX / 2;
  const cell = GLYPH_BOX / PATCH;
  for (let tile = 0; tile < TILE_COUNT; tile += 1) {
    const cx = TILE_CENTER_X[tile];
    const cy = TILE_CENTER_Y[tile];
    for (let v = 0; v < PATCH; v += 1) {
      for (let u = 0; u < PATCH; u += 1) {
        const gx = cx - half + (u + 0.5) * cell;
        const gy = cy - half + (v + 0.5) * cell;
        let sum = 0;
        for (let o = 0; o < 8; o += 2) {
          sum += sampleCanvas(image, m, gx + PATCH_OFFSETS[o] * cell, gy + PATCH_OFFSETS[o + 1] * cell);
        }
        out[tile * CELLS + v * PATCH + u] = sum / 4;
      }
    }
  }
  return out;
}

/** Sorts the 64 cells of the patch at `values[offset]` ascending into `SORTED` (`total_cmp` order). */
function sortCells(values, offset) {
  for (let c = 0; c < CELLS; c += 1) SORTED[c] = values[offset + c];
  SORTED.sort();
}

/**
 * The robust darkest and brightest level of a patch, `[low, high]`: the values `PATCH_CUT` cells
 * in from either end of the sorted cells. Exported for tests only.
 */
export function patchLevels(values, offset = 0) {
  sortCells(values, offset);
  return [SORTED[PATCH_CUT], SORTED[CELLS - 1 - PATCH_CUT]];
}

/**
 * Maps the darkest level of the patch at `values[offset]` to 0 and its brightest to 1, with
 * `floor` as the smallest span that counts as contrast, clamped to [-0.25, 1.25]; writes the 64
 * results to `out[offset]` (`out` may be `values`) and returns the span `high - low` before the
 * floor. Exported for tests only.
 */
export function rescale(values, offset, floor, out) {
  sortCells(values, offset);
  const low = SORTED[PATCH_CUT];
  const high = SORTED[CELLS - 1 - PATCH_CUT];
  const range = fmax(high - low, floor);
  for (let c = 0; c < CELLS; c += 1) {
    out[offset + c] = clamp((values[offset + c] - low) / range, -0.25, 1.25);
  }
  return high - low;
}

/**
 * Picks for every patch the polarity and glyph whose template matches best.
 *
 * The template blur is chosen per frame, by the lowest total error. With `rescaleTemplates` the
 * templates are rescaled like the patches; tiles flagged in `erased` (a byte per tile, or `null`
 * for none) get zero margins, so they are the first the Reed-Solomon decoder treats as erasures.
 */
function classify(patches, sigmas, rescaleTemplates, erased) {
  let bestTotal = Number.MAX_VALUE;
  let best = newReads();
  let reads = newReads();
  for (const sigma of sigmas) {
    const pred = patternsFor(sigma, rescaleTemplates);
    let total = 0;
    for (let tile = 0; tile < TILE_COUNT; tile += 1) {
      const patchBase = tile * CELLS;
      for (let hypothesis = 0; hypothesis < HYPOTHESES; hypothesis += 1) {
        const predBase = hypothesis * CELLS;
        let error = 0;
        for (let c = 0; c < CELLS; c += 1) {
          const d = patches[patchBase + c] - pred[predBase + c];
          error += d * d;
        }
        ERRORS[hypothesis] = error;
      }
      let bestHypothesis = 0;
      for (let hypothesis = 1; hypothesis < HYPOTHESES; hypothesis += 1) {
        if (totalCmp(ERRORS[hypothesis], ERRORS[bestHypothesis]) < 0) {
          bestHypothesis = hypothesis;
        }
      }
      const polarity = bestHypothesis >> 4;
      const glyph = bestHypothesis & 15;
      const bestError = ERRORS[bestHypothesis];
      let otherPolarity = Number.MAX_VALUE;
      for (let g = 0; g < GLYPH_COUNT; g += 1) {
        otherPolarity = fmin(otherPolarity, ERRORS[(1 - polarity) * GLYPH_COUNT + g]);
      }
      let otherGlyph = Number.MAX_VALUE;
      for (let g = 0; g < GLYPH_COUNT; g += 1) {
        if (g !== glyph) otherGlyph = fmin(otherGlyph, ERRORS[polarity * GLYPH_COUNT + g]);
      }
      total += bestError;
      const unreadable = erased !== null && erased[tile] === 1;
      reads.light[tile] = polarity;
      reads.glyph[tile] = glyph;
      reads.polarityMargin[tile] = unreadable ? 0 : otherPolarity - bestError;
      reads.glyphMargin[tile] = unreadable ? 0 : otherGlyph - bestError;
      reads.error[tile] = bestError;
    }
    reads.count = TILE_COUNT;
    if (total < bestTotal) {
      bestTotal = total;
      const swap = best;
      best = reads;
      reads = swap;
    }
  }
  return best;
}

/**
 * The level read: every patch is judged against the light and dark levels measured at the
 * finders, interpolated to the tile. `patches` is the output of {@link samplePatches}. Exported
 * for tests only.
 */
export function readTiles(patches, reference, sigmas) {
  for (let tile = 0; tile < TILE_COUNT; tile += 1) {
    const u = clampUnit(TILE_CENTER_X[tile] / 1024);
    const v = clampUnit(TILE_CENTER_Y[tile] / 1024);
    const lit = mixCorners(reference.lit, u, v);
    const dark = mixCorners(reference.dark, u, v);
    const base = tile * CELLS;
    for (let c = 0; c < CELLS; c += 1) {
      WORK[base + c] = (patches[base + c] - dark) / (lit - dark);
    }
  }
  return classify(WORK, sigmas, false, null);
}

/** Raw tile patches and finder levels from one independently decoded capture. */
export function tileEvidence(image, frame, options = DEFAULT_DECODE_OPTIONS) {
  if (!isDecodable(image, options) || (frame.inferredCorner !== null &&
      (!Number.isInteger(frame.inferredCorner) || frame.inferredCorner < 0 || frame.inferredCorner > 3))) {
    return null;
  }
  const m = frame.homography.values;
  const reference = referenceLevels(image, m, frame.inferredCorner);
  return reference === null ? null : { patches: samplePatches(image, m), reference };
}

/** Finder-level-normalised patches, with each capture levelled before it is averaged. */
function levelledPatches(patches, reference) {
  const out = new Float64Array(TILE_COUNT * CELLS);
  for (let tile = 0; tile < TILE_COUNT; tile += 1) {
    const u = clampUnit(TILE_CENTER_X[tile] / 1024);
    const v = clampUnit(TILE_CENTER_Y[tile] / 1024);
    const lit = mixCorners(reference.lit, u, v);
    const dark = mixCorners(reference.dark, u, v);
    const base = tile * CELLS;
    for (let c = 0; c < CELLS; c += 1) {
      out[base + c] = (patches[base + c] - dark) / (lit - dark);
    }
  }
  return out;
}

/** Sequential cell-by-cell mean, matching the reference's floating-point sum order. */
function meanPatches(sets) {
  const mean = new Float64Array(TILE_COUNT * CELLS);
  for (const set of sets) {
    for (let i = 0; i < mean.length; i += 1) mean[i] += set[i];
  }
  for (let i = 0; i < mean.length; i += 1) mean[i] /= sets.length;
  return mean;
}

/** Tile lanes recovered from captures of one shown frame; the caller checks lane headers. */
export function mergeTiles(evidence, options = DEFAULT_DECODE_OPTIONS) {
  if (evidence.length === 0) return { p: null, k: null };
  const levelled = meanPatches(evidence.map((e) => levelledPatches(e.patches, e.reference)));
  let words = tileWords(classify(levelled, options.templateSigmas, false, null));
  let p = decodeWithErasures("P", words.p, words.pConfidence);
  let k = decodeWithErasures("K", words.k, words.kConfidence);
  if (p === null || k === null) {
    const raw = meanPatches(evidence.map((e) => e.patches));
    words = tileWords(readTilesNormalised(raw, options.templateSigmas));
    if (p === null) p = decodeWithErasures("P", words.p, words.pConfidence);
    if (k === null) k = decodeWithErasures("K", words.k, words.kConfidence);
  }
  return { p, k };
}

/**
 * The normalised read: every patch and every template is rescaled by its own contrast before
 * they are compared, so the judgement does not depend on absolute levels. Tiles whose contrast
 * is below `WEAK_TILE` times the median contrast are erased. Exported for tests only.
 */
export function readTilesNormalised(patches, sigmas) {
  for (let tile = 0; tile < TILE_COUNT; tile += 1) {
    SPANS[tile] = rescale(patches, tile * CELLS, PATCH_SPAN_FLOOR, WORK);
  }
  SPANS_SORTED.set(SPANS);
  SPANS_SORTED.sort();
  const median = SPANS_SORTED[TILE_COUNT >> 1];
  for (let tile = 0; tile < TILE_COUNT; tile += 1) {
    ERASED[tile] = SPANS[tile] < WEAK_TILE * median ? 1 : 0;
  }
  return classify(WORK, sigmas, true, ERASED);
}

/**
 * Packs tile reads into lane P and K words with per-byte confidence. Exported for tests only.
 */
export function tileWords(reads) {
  const p = new Uint8Array(P_WORD);
  const pConfidence = new Float64Array(P_WORD).fill(Number.MAX_VALUE);
  const k = new Uint8Array(K_WORD);
  const kConfidence = new Float64Array(K_WORD).fill(Number.MAX_VALUE);
  for (let tile = 0; tile < reads.count; tile += 1) {
    if (reads.light[tile] === 1) {
      p[tile >> 3] |= 1 << (7 - (tile & 7));
    }
    pConfidence[tile >> 3] = fmin(pConfidence[tile >> 3], reads.polarityMargin[tile]);
    k[tile >> 1] |= (tile & 1) === 0 ? reads.glyph[tile] << 4 : reads.glyph[tile];
    kConfidence[tile >> 1] = fmin(kConfidence[tile >> 1], fmin(reads.glyphMargin[tile], reads.polarityMargin[tile]));
  }
  return { p, pConfidence, k, kConfidence };
}

/**
 * Lanes P and K from one set of patches: the level read first, then, for any lane still
 * unreadable, the normalised read. Returns `{p, k}` (each a lane result or `null`). Exported for
 * tests only.
 */
export function readTileLanes(patches, reference, sigmas) {
  let words = tileWords(readTiles(patches, reference, sigmas));
  let p = decodeWithErasures("P", words.p, words.pConfidence);
  let k = decodeWithErasures("K", words.k, words.kConfidence);
  if (p === null || k === null) {
    words = tileWords(readTilesNormalised(patches, sigmas));
    if (p === null) {
      p = decodeWithErasures("P", words.p, words.pConfidence);
    }
    if (k === null) {
      k = decodeWithErasures("K", words.k, words.kConfidence);
    }
  }
  return { p, k };
}

/**
 * The orientation hypotheses `{rotation, mirrored, m}` of a finder quad: four quarter turns, and
 * four mirrored ones when `tryMirrored`. Exported for tests only.
 */
export function hypotheses(finders, tryMirrored) {
  const srcX = CANONICAL_X;
  const srcY = CANONICAL_Y;
  const out = [];
  for (const mirrored of [false, true]) {
    if (mirrored && !tryMirrored) {
      continue;
    }
    for (let rotation = 0; rotation < 4; rotation += 1) {
      const dstX = new Float64Array(4);
      const dstY = new Float64Array(4);
      for (let i = 0; i < 4; i += 1) {
        const q = mirrored ? finders[(rotation + 4 - i) % 4] : finders[(i + rotation) % 4];
        dstX[i] = q.x;
        dstY[i] = q.y;
      }
      const m = homographyFromPoints(srcX, srcY, dstX, dstY);
      if (m !== null) {
        out.push({ rotation, mirrored, m });
      }
    }
  }
  return out;
}

/** Everything read from one camera frame. */
export class PetalDecodedFrame {
  constructor(homography, rotation, mirrored, p, k, d, inferredCorner) {
    /** Canvas-to-pixel homography that was used. */
    this.homography = homography;
    /** Orientation: how many quarter turns the code is rotated. */
    this.rotation = rotation;
    /** Whether the image was mirrored. */
    this.mirrored = mirrored;
    /** Lane P result (`{data, corrected, erasures}`) or `null`. */
    this.p = p;
    /** Lane K result or `null`. */
    this.k = k;
    /** Lane D result or `null`. */
    this.d = d;
    /**
     * The corner finder that was hidden (by a finger, a glare or the edge of the frame) and
     * inferred from the other three, as its canonical index: 0 top-left, 1 top-right,
     * 2 bottom-right, 3 bottom-left of the upright code; `null` when all four were seen.
     */
    this.inferredCorner = inferredCorner;
    Object.freeze(this);
  }

  /** Number of lanes that decoded. */
  lanesOk() {
    return (this.p !== null ? 1 : 0) + (this.k !== null ? 1 : 0) + (this.d !== null ? 1 : 0);
  }

  /** What lane D carried, when it decoded (see `parseDLane`). */
  dLane() {
    return this.d === null ? null : parseDLane(this.d.data);
  }

  /** The beacon, when lane D decoded on a beacon frame. */
  beacon() {
    const lane = this.dLane();
    return lane !== null && lane.type === "beacon" ? lane.beacon : null;
  }

  /** Atom packets from every lane that decoded (P, K, then D). */
  atomPackets() {
    const packets = [];
    if (this.p !== null) {
      const packet = parseAtomLane("P", this.p.data);
      if (packet !== null) packets.push(packet);
    }
    if (this.k !== null) {
      const packet = parseAtomLane("K", this.k.data);
      if (packet !== null) packets.push(packet);
    }
    const lane = this.dLane();
    if (lane !== null && lane.type === "atoms") {
      packets.push(lane.packet);
    }
    return packets;
  }

  /** Offers everything this frame carries to `assembler` (D first, then P and K). */
  feed(assembler) {
    const lane = this.dLane();
    if (lane !== null) {
      assembler.pushDLane(lane);
    }
    if (this.p !== null) {
      const packet = parseAtomLane("P", this.p.data);
      if (packet !== null) assembler.pushAtoms(packet);
    }
    if (this.k !== null) {
      const packet = parseAtomLane("K", this.k.data);
      if (packet !== null) assembler.pushAtoms(packet);
    }
  }
}

/**
 * Reads every lane under one orientation. `d` (an already decoded lane D, or
 * `null`) skips work the caller has done; the result is identical either way
 * because every read is a pure function of its inputs.
 */
function finish(image, options, candidate, d, inferredCorner) {
  const laneD = d !== null ? d : readLaneD(image, candidate.m, candidate.reference);
  const patches = samplePatches(image, candidate.m, PATCHES);
  const tiles = readTileLanes(patches, candidate.reference, options.templateSigmas);
  return new PetalDecodedFrame(
    new PetalHomography(candidate.m),
    candidate.rotation,
    candidate.mirrored,
    tiles.p,
    tiles.k,
    laneD,
    inferredCorner,
  );
}

function isByteArray(value) {
  return value instanceof Uint8Array || value instanceof Uint8ClampedArray;
}

function requireLumaShape(image) {
  if (
    image === null ||
    typeof image !== "object" ||
    !Number.isInteger(image.width) ||
    !Number.isInteger(image.height) ||
    image.width < 0 ||
    image.height < 0 ||
    !isByteArray(image.data)
  ) {
    throw new TypeError("image must be a PetalLuma or {width, height, data: Uint8Array}");
  }
}

/**
 * Whether `image` is something the decoder may work on: at least 48 pixels on a side, within
 * `maxPixels`, and with a buffer that matches its size.
 */
function isDecodable(image, options) {
  return (
    image.width >= 48 &&
    image.height >= 48 &&
    image.width * image.height <= options.maxPixels &&
    image.data.length === image.width * image.height
  );
}

/**
 * Decodes one frame; returns `{frame}` or `{error}` with a `PetalError` code.
 * Shared by `decodePetalFrame` and the scan session.
 *
 * Tries the finder candidates of `finderCandidates` in order and returns the
 * first that reads.
 */
export function decodeFrameResult(image, options) {
  requireLumaShape(image);
  if (!isDecodable(image, options)) {
    return { error: "unsupported_image" };
  }
  let located = false;
  for (const set of finderCandidates(image)) {
    located = true;
    const frame = decodeCandidate(image, options, set);
    if (frame !== null) {
      return { frame };
    }
  }
  return { error: located ? "no_orientation" : "no_finders" };
}

/**
 * One finder set: an inferred corner is first refined against the rings; the
 * orientation hypotheses are ranked by gate score plus `天` score; lane D is
 * tried under the best three whose gate score is at least 0.2, then the tile
 * lanes under the best four.
 */
function decodeCandidate(image, options, set) {
  const corners = set.inferred === null ? set.corners : refineInferredCorner(image, set.corners, set.inferred);
  const inferredCorner = (rotation, mirrored) =>
    set.inferred === null ? null : canonicalCorner(set.inferred, rotation, mirrored);
  const scored = [];
  for (const hypothesis of hypotheses(corners, options.tryMirrored)) {
    const reference = referenceLevels(image, hypothesis.m, inferredCorner(hypothesis.rotation, hypothesis.mirrored));
    if (reference === null) continue;
    scored.push({
      ...hypothesis,
      reference,
      gate: gateScore(image, hypothesis.m, reference),
      mask: maskScore(image, hypothesis.m, reference),
    });
  }
  // a stable sort, like the reference's
  scored.sort((a, b) => totalCmp(b.gate + b.mask, a.gate + a.mask));
  // 1. the ring beacon is the cheapest and strongest orientation check; the
  // ranking is not by gate score, so a weak gate skips to the next hypothesis
  for (const candidate of scored.slice(0, 3)) {
    if (candidate.gate < 0.2) {
      continue;
    }
    const d = readLaneD(image, candidate.m, candidate.reference);
    if (d !== null) {
      return finish(image, options, candidate, d, inferredCorner(candidate.rotation, candidate.mirrored));
    }
  }
  // 2. fall back to the tile lanes under the most promising orientations
  for (const candidate of scored.slice(0, 4)) {
    const patches = samplePatches(image, candidate.m, PATCHES);
    const tiles = readTileLanes(patches, candidate.reference, options.templateSigmas);
    if (tiles.p !== null || tiles.k !== null) {
      return new PetalDecodedFrame(
        new PetalHomography(candidate.m),
        candidate.rotation,
        candidate.mirrored,
        tiles.p,
        tiles.k,
        readLaneD(image, candidate.m, candidate.reference),
        inferredCorner(candidate.rotation, candidate.mirrored),
      );
    }
  }
  return null;
}

/**
 * Decodes one camera frame.
 *
 * The finder candidates are tried in order: four corner blossoms, or three
 * that form a corner with the fourth inferred (hidden by a finger, a glare or
 * the edge of the frame; reported in `inferredCorner`). Orientations are
 * ranked by the ring gates plus the `天`. Lanes P and K are read against the
 * light and dark levels measured at the finders first; a lane that does not
 * decode that way is re-read with a normalised read that rescales every tile
 * by its own contrast (over-exposure, veiling light, glare and shadows
 * cancel). An orientation is accepted when lane D, P or K decodes.
 *
 * @param {{width: number, height: number, data: Uint8Array | Uint8ClampedArray}} image luma plane
 * @param {{tryMirrored?: boolean, templateSigmas?: readonly number[], maxPixels?: number}} [options]
 * @returns {PetalDecodedFrame}
 * @throws {PetalError} `unsupported_image` (smaller than 48 pixels on a side,
 *   larger than `maxPixels` or inconsistent), `no_finders` or `no_orientation`
 */
export function decodePetalFrame(image, options) {
  const result = decodeFrameResult(image, resolveDecodeOptions(options));
  if (result.error !== undefined) {
    throw new PetalError(result.error);
  }
  return result.frame;
}

function homographyValues(homography) {
  if (homography instanceof PetalHomography) {
    return Float64Array.from(homography.values);
  }
  if (homography !== null && typeof homography === "object" && homography.length === 9) {
    return Float64Array.from(homography);
  }
  throw new TypeError("homography must be a PetalHomography or nine coefficients");
}

/** The inferred canonical corner of a decoded frame (`null` when it has none). */
function inferredCornerOf(frame) {
  const corner = frame.inferredCorner ?? null;
  if (corner !== null && !(Number.isInteger(corner) && corner >= 0 && corner < 4)) {
    throw new TypeError("inferredCorner must be null or a corner index 0..3");
  }
  return corner;
}

/**
 * Follows a code from the previous frame that decoded; returns the frame or `null`. The shared
 * part of `trackPetalFrame` and the scan session (arguments already validated).
 */
export function trackFrame(image, previous, options) {
  requireLumaShape(image);
  if (!isDecodable(image, options)) {
    return null;
  }
  const h0 = homographyValues(previous.homography);
  const previousInferred = inferredCornerOf(previous);
  const span = (a, b) => Math.sqrt((a[0] - b[0]) * (a[0] - b[0]) + (a[1] - b[1]) * (a[1] - b[1]));
  const expected = FINDER_CENTERS.map(([cx, cy]) => {
    const [x, y] = applyHomography(h0, cx, cy);
    const size = fmax(
      span(applyHomography(h0, cx - 60, cy), applyHomography(h0, cx + 60, cy)),
      span(applyHomography(h0, cx, cy - 60), applyHomography(h0, cx, cy + 60)),
    );
    return { x, y, size };
  });
  // a broken previous pose (non-finite, or finders larger than the image) is not followed
  const short = Math.min(image.width, image.height);
  if (
    expected.some(
      (finder) =>
        !(Number.isFinite(finder.x) && Number.isFinite(finder.y) && Number.isFinite(finder.size)) || finder.size > short,
    )
  ) {
    return null;
  }
  // every corner but the one inferred in the previous frame is followed
  const found = expected.map((finder, index) => (previousInferred === index ? null : followFinder(image, finder)));
  // the mean movement of the corners that were followed predicts the others
  let sumX = -0;
  let sumY = -0;
  let moved = 0;
  for (let index = 0; index < 4; index += 1) {
    if (found[index] === null) continue;
    sumX += found[index].x - expected[index].x;
    sumY += found[index].y - expected[index].y;
    moved += 1;
  }
  if (moved < 3) {
    return null;
  }
  const shiftX = sumX / moved;
  const shiftY = sumY / moved;
  const predicted = (index) => ({
    x: expected[index].x + shiftX,
    y: expected[index].y + shiftY,
    size: expected[index].size,
  });
  // a corner that was hidden is seen again only when its blossom is found right where the
  // others say it is (a bright thumb beside it must not count)
  if (previousInferred !== null) {
    const at = predicted(previousInferred);
    const again = followFinder(image, at);
    found[previousInferred] =
      again !== null && Math.sqrt((again.x - at.x) * (again.x - at.x) + (again.y - at.y) * (again.y - at.y)) <= 0.25 * at.size
        ? again
        : null;
  }
  const lost = [0, 1, 2, 3].filter((index) => found[index] === null);
  let inferred = null;
  if (lost.length === 1) {
    inferred = lost[0];
    found[inferred] = predicted(inferred);
  } else if (lost.length > 1) {
    return null;
  }
  const corners = inferred === null ? found : refineInferredCorner(image, found, inferred);
  const m = homographyFromPoints(
    CANONICAL_X,
    CANONICAL_Y,
    Float64Array.from(corners, (finder) => finder.x),
    Float64Array.from(corners, (finder) => finder.y),
  );
  if (m === null) {
    return null;
  }
  const reference = referenceLevels(image, m, inferred);
  if (reference === null) {
    return null;
  }
  const d = readLaneD(image, m, reference);
  const patches = samplePatches(image, m, PATCHES);
  const tiles = readTileLanes(patches, reference, options.templateSigmas);
  if (tiles.p === null && tiles.k === null && d === null) {
    return null;
  }
  return new PetalDecodedFrame(
    new PetalHomography(m),
    previous.rotation,
    previous.mirrored,
    tiles.p,
    tiles.k,
    d,
    inferred,
  );
}

/**
 * Follows a code from the previous frame that decoded, without searching the whole image for
 * finders (the most expensive part of {@link decodePetalFrame}).
 *
 * Each corner finder is re-found near where the previous pose puts it; a corner inferred in the
 * previous frame is seen again only when its blossom is found within a quarter diameter of where
 * the mean movement of the others puts it. When exactly one corner is not found it is placed by
 * that mean movement and refined against the rings like an inferred corner. The orientation is
 * kept from the previous frame. Returns `null` for a broken previous pose, when two corners are
 * lost or when no lane decodes; the caller then runs {@link decodePetalFrame}. A
 * {@link PetalScanSession} does this by itself.
 *
 * @param {{width: number, height: number, data: Uint8Array | Uint8ClampedArray}} image luma plane
 * @param {PetalDecodedFrame} previous the last frame that decoded
 * @param {{tryMirrored?: boolean, templateSigmas?: readonly number[], maxPixels?: number}} [options]
 * @returns {PetalDecodedFrame | null}
 */
export function trackPetalFrame(image, previous, options) {
  const resolved = resolveDecodeOptions(options);
  if (!(previous instanceof PetalDecodedFrame)) {
    throw new TypeError("previous must be a PetalDecodedFrame");
  }
  return trackFrame(image, previous, resolved);
}

/**
 * Reads all lanes with a known canvas-to-pixel homography (no finder search).
 *
 * Returns `null` when the image is unusable or the finder reference levels
 * are too weak. Used by refinement passes and by qualification tooling with a
 * ground-truth pose; {@link trackPetalFrame} follows a moving code.
 */
export function decodePetalFrameAt(image, homography, options) {
  const resolved = resolveDecodeOptions(options);
  requireLumaShape(image);
  const m = homographyValues(homography);
  if (!isDecodable(image, resolved)) {
    return null;
  }
  const reference = referenceLevels(image, m);
  if (reference === null) {
    return null;
  }
  return finish(image, resolved, { m, rotation: 0, mirrored: false, reference }, null, null);
}

/**
 * Builds the cells a decoder believes it saw, for diagnostics; `null` when the image is unusable
 * or the finder reference levels are too weak. The levels of the frame's inferred corner, if
 * any, are extrapolated as in the decoder.
 *
 * Tiles are taken from the level read (the one that judges against the finder levels), even for
 * a frame whose lanes were rescued by the normalised read.
 */
export function observedCells(image, frame, options) {
  const resolved = resolveDecodeOptions(options);
  requireLumaShape(image);
  const m = homographyValues(frame.homography);
  const inferred = inferredCornerOf(frame);
  if (!isDecodable(image, resolved)) {
    return null;
  }
  const reference = referenceLevels(image, m, inferred);
  if (reference === null) {
    return null;
  }
  const patches = samplePatches(image, m, PATCHES);
  const words = tileWords(readTiles(patches, reference, resolved.templateSigmas));
  const dots = readDots(image, m, reference);
  return PetalFrameCells.fromWords(words.p, words.k, dots.word);
}

/**
 * Mean squared tile-match error of the level read, a quick image-quality indicator; `null` when
 * the image is unusable or the finder reference levels are too weak.
 *
 * It can be large for a frame whose lanes were rescued by the normalised read, which is the
 * point: the finder levels did not describe that picture.
 */
export function tileMatchError(image, frame, options) {
  const resolved = resolveDecodeOptions(options);
  requireLumaShape(image);
  const m = homographyValues(frame.homography);
  const inferred = inferredCornerOf(frame);
  if (!isDecodable(image, resolved)) {
    return null;
  }
  const reference = referenceLevels(image, m, inferred);
  if (reference === null) {
    return null;
  }
  const reads = readTiles(samplePatches(image, m, PATCHES), reference, resolved.templateSigmas);
  let total = -0;
  for (let tile = 0; tile < reads.count; tile += 1) total += reads.error[tile];
  return total / reads.count;
}
