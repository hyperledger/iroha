# Copyright 2026 Hyperledger Iroha Contributors
# SPDX-License-Identifier: Apache-2.0

"""From a camera luma plane to lane data.

The decoder locates the corner finders, derives a homography for each
orientation hypothesis, ranks the hypotheses by their ring gates and the ``天``
mask, picks the one whose lane ``D`` codeword checks out (or whose tile lanes
read), then reads the tiles and dots. Every tile is classified *jointly*: the
8x8 sample patch is compared against the 32 hypotheses (polarity x glyph) and
the best match wins, so the katakana and the light/dark bit help each other.
Cells the decoder is unsure about become Reed-Solomon erasures.

When a thumb, a glare or the edge of the frame hides one corner blossom, the
other three locate the code and the hidden corner is inferred, then moved to
where the three dotted rings line up best. :func:`track_frame` follows a code
from the previous frame's pose without searching the whole image.

The tile *level read* judges every patch against the light and dark levels
measured at the finders. When it leaves lane ``P`` or ``K`` unreadable, the
*normalised read* is tried: it rescales each patch (and each template) by its
own contrast, so over-exposure, veiling light, glare, shadows and gradients
cancel out.

This is an operation-by-operation port of the Rust reference in IEEE double
precision, including the order of every floating-point sum, so it reads the
same lanes from the same pixels.
"""

from __future__ import annotations

import enum
import math
from dataclasses import dataclass, replace
from functools import reduce
from operator import add, mul, sub
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from ._numeric import F64_MAX, NAN, f64_max, f64_min, ieee_div, total_key
from .glyphs import GLYPH_COUNT, TEMPLATE_N, TEMPLATES
from .image import Homography, Luma
from .lanes import D_WORD, K_WORD, P_WORD, FrameCells, Lane, decode_lane_counted
from .layout import (
    FINDER_CENTERS,
    GLYPH_BOX,
    MASK,
    RING_COUNT,
    TILE_COUNT,
    TILE_ORIGIN,
    TILE_PITCH,
    TOTAL_SLOTS,
    data_slots,
    gate_slots,
    guard_slots,
    slot_center,
    split_slot,
    tile_center,
)
from .locate import Finder, FinderSet, candidates, follow
from .rs import RsError
from .stream import AtomPacket, Beacon, DLane, StreamAssembler, parse_atom_lane, parse_d_lane

__all__ = [
    "DecodeOptions",
    "LaneResult",
    "DecodedFrame",
    "DecodeErrorKind",
    "DecodeError",
    "decode_frame",
    "decode_frame_at",
    "track_frame",
    "observed_cells",
    "tile_match_error",
    "INK_ON_LIGHT",
    "PINK_ON_DARK",
]

_PATCH = TEMPLATE_N
_CELLS = _PATCH * _PATCH
_HYPOTHESES = 2 * GLYPH_COUNT
#: Relative level of the glyph ink on a light tile (ink / light fill).
INK_ON_LIGHT = 0.04
#: Relative level of a pink glyph on a dark tile (pink / light fill).
PINK_ON_DARK = 0.83
#: Cells cut from each end of a sorted patch to find its robust darkest and brightest level.
_PATCH_CUT = _CELLS // 10
#: Tiles whose contrast is below this fraction of the median tile contrast become erasures
#: in the normalised read.
_WEAK_TILE = 0.25


@dataclass(frozen=True)
class DecodeOptions:
    """Decoder tuning."""

    #: Also try horizontally mirrored images (front-camera previews).
    try_mirrored: bool = True
    #: Blur widths (in template cells) tried for glyph matching.
    template_sigmas: Tuple[float, ...] = (0.0, 0.5, 0.8, 1.1, 1.5)
    #: Largest image (in pixels) the decoder accepts; larger frames should be
    #: downscaled by the caller. Bounds memory and work on hostile input.
    max_pixels: int = 12_000_000

    def __post_init__(self) -> None:
        object.__setattr__(self, "template_sigmas", tuple(float(s) for s in self.template_sigmas))


@dataclass(frozen=True)
class LaneResult:
    """A lane that passed its Reed-Solomon check."""

    #: Lane data bytes (header and atoms, or the beacon).
    data: bytes
    #: Byte positions the Reed-Solomon decoder rewrote: the erased bytes plus
    #: any errors it found among the others (a measure of how close the lane
    #: was to failing).
    corrected: int
    #: Bytes that were passed to the decoder as erasures.
    erasures: int


@dataclass(frozen=True)
class DecodedFrame:
    """Everything read from one camera frame."""

    #: Canvas-to-pixel homography that was used.
    homography: Homography
    #: Orientation: how many quarter turns the code is rotated.
    rotation: int
    #: Whether the image was mirrored.
    mirrored: bool
    #: Lane ``P`` result.
    p: Optional[LaneResult]
    #: Lane ``K`` result.
    k: Optional[LaneResult]
    #: Lane ``D`` result.
    d: Optional[LaneResult]
    #: The corner finder that was hidden (by a finger, a glare or the edge of
    #: the frame) and inferred from the other three, as its canonical index:
    #: 0 top-left, 1 top-right, 2 bottom-right, 3 bottom-left of the upright code.
    inferred_corner: Optional[int] = None

    @property
    def lanes_ok(self) -> int:
        """Number of lanes that decoded."""
        return (self.p is not None) + (self.k is not None) + (self.d is not None)

    @property
    def lanes(self) -> str:
        """Lanes that decoded, as letters from ``"PKD"``."""
        return "".join(
            letter
            for letter, result in (("P", self.p), ("K", self.k), ("D", self.d))
            if result is not None
        )

    def d_lane(self) -> Optional[DLane]:
        """What lane ``D`` carried, when it decoded."""
        if self.d is None:
            return None
        return parse_d_lane(self.d.data)

    def beacon(self) -> Optional[Beacon]:
        """The beacon, when lane ``D`` decoded on a beacon frame."""
        lane = self.d_lane()
        return lane if isinstance(lane, Beacon) else None

    def atom_packets(self) -> List[AtomPacket]:
        """Atom packets from every lane that decoded."""
        packets = []
        for lane, result in ((Lane.P, self.p), (Lane.K, self.k)):
            if result is not None:
                packet = parse_atom_lane(lane, result.data)
                if packet is not None:
                    packets.append(packet)
        d_lane = self.d_lane()
        if isinstance(d_lane, AtomPacket):
            packets.append(d_lane)
        return packets

    def feed(self, assembler: StreamAssembler) -> None:
        """Offer everything this frame carries to ``assembler``."""
        d_lane = self.d_lane()
        if d_lane is not None:
            assembler.push_d_lane(d_lane)
        for lane, result in ((Lane.P, self.p), (Lane.K, self.k)):
            if result is not None:
                packet = parse_atom_lane(lane, result.data)
                if packet is not None:
                    assembler.push_atoms(packet)


class DecodeErrorKind(enum.Enum):
    """Why a frame could not be decoded at all."""

    #: The image is empty, smaller than 48 pixels on a side, or larger than
    #: :attr:`DecodeOptions.max_pixels`.
    UNSUPPORTED_IMAGE = "petal image has an unsupported size"
    #: The four corner finders were not found.
    NO_FINDERS = "petal finders not found"
    #: Finders were found but no orientation produced a readable lane.
    NO_ORIENTATION = "no petal orientation produced a readable lane"


class DecodeError(Exception):
    """A frame could not be decoded; :attr:`kind` says why."""

    def __init__(self, kind: DecodeErrorKind) -> None:
        super().__init__(kind.value)
        self.kind = kind


Projector = Callable[[float, float], float]


def _projector(image: Luma, h: Homography) -> Projector:
    """``image.sample(*h.apply(x, y))`` as one fast closure."""
    m0, m1, m2, m3, m4, m5, m6, m7, m8 = h.m
    data = image.data
    w = image.width
    wm1 = w - 1
    hm1 = image.height - 1
    fwm1 = float(wm1)
    fhm1 = float(hm1)

    def project(x: float, y: float) -> float:
        den = m6 * x + m7 * y + m8
        if den == 0.0:
            px = ieee_div(m0 * x + m1 * y + m2, den)
            py = ieee_div(m3 * x + m4 * y + m5, den)
        else:
            px = (m0 * x + m1 * y + m2) / den
            py = (m3 * x + m4 * y + m5) / den
        fx = px - 0.5
        fy = py - 0.5
        if fx != fx or fy != fy:
            return NAN
        if fx < 0.0:
            fx = 0.0
        elif fx > fwm1:
            fx = fwm1
        if fy < 0.0:
            fy = 0.0
        elif fy > fhm1:
            fy = fhm1
        x0 = int(fx)
        y0 = int(fy)
        x1 = x0 + 1 if x0 < wm1 else wm1
        y1 = y0 + 1 if y0 < hm1 else hm1
        tx = fx - x0
        ty = fy - y0
        r0 = y0 * w
        r1 = y1 * w
        top = data[r0 + x0] * (1.0 - tx) + data[r0 + x1] * tx
        bottom = data[r1 + x0] * (1.0 - tx) + data[r1 + x1] * tx
        return top * (1.0 - ty) + bottom * ty

    return project


class _Reference:
    """Lit and dark levels measured at the four finders."""

    __slots__ = ("lit", "dark")

    def __init__(self, lit: Tuple[float, ...], dark: Tuple[float, ...]) -> None:
        self.lit = lit
        self.dark = dark

    def at(self, x: float, y: float) -> Tuple[float, float]:
        """Bilinear interpolation over the canvas of the four corner estimates."""
        u = x / 1024.0
        if u < 0.0:
            u = 0.0
        elif u > 1.0:
            u = 1.0
        v = y / 1024.0
        if v < 0.0:
            v = 0.0
        elif v > 1.0:
            v = 1.0
        lit = self.lit
        dark = self.dark
        top = lit[0] * (1.0 - u) + lit[1] * u
        bottom = lit[3] * (1.0 - u) + lit[2] * u
        lit_level = top * (1.0 - v) + bottom * v
        top = dark[0] * (1.0 - u) + dark[1] * u
        bottom = dark[3] * (1.0 - u) + dark[2] * u
        return lit_level, top * (1.0 - v) + bottom * v


def _dot_samples(project: Projector, x: float, y: float, spread: float) -> float:
    total = project(x + 0.0, y + 0.0)
    total += project(x + spread, y + 0.0)
    total += project(x + -spread, y + 0.0)
    total += project(x + 0.0, y + spread)
    total += project(x + 0.0, y + -spread)
    return total / 5.0


# the blossom is solid out to radius 24 around its centre
_FINDER_RING = tuple(
    (20.0 * math.cos(math.tau * k / 8.0), 20.0 * math.sin(math.tau * k / 8.0)) for k in range(8)
)


def _reference_levels(project: Projector, inferred: Optional[int] = None) -> Optional[_Reference]:
    """Light and dark levels at the four corners: the solid blossom core, and the black
    canvas 100 units inward of it.

    An ``inferred`` corner (canonical index) was not seen, so its levels are
    extrapolated from the other three by the parallelogram rule and kept within their
    range; they must differ by 12 like a seen corner's.
    """
    lit = [0.0] * 4
    dark = [0.0] * 4
    for i, (cx, cy) in enumerate(FINDER_CENTERS):
        if i == inferred:
            continue
        total = project(cx, cy)
        for ox, oy in _FINDER_RING:
            total += project(cx + ox, cy + oy)
        lit_level = total / 9.0
        sx = 1.0 if cx < 512.0 else -1.0
        sy = 1.0 if cy < 512.0 else -1.0
        a = _dot_samples(project, cx + sx * 100.0, cy, 5.0)
        b = _dot_samples(project, cx, cy + sy * 100.0, 5.0)
        dark_level = 0.5 * (a + b)
        contrast = lit_level - dark_level
        # also refuses NaN levels, which only a non-finite pose can produce
        if not math.isfinite(contrast) or contrast < 12.0:
            return None
        lit[i] = lit_level
        dark[i] = dark_level
    if inferred is not None:
        m = inferred
        n1 = (m + 1) % 4
        opposite = (m + 2) % 4
        n2 = (m + 3) % 4
        for levels in (lit, dark):
            low = min(levels[n1], levels[opposite], levels[n2])
            high = max(levels[n1], levels[opposite], levels[n2])
            value = levels[n1] + levels[n2] - levels[opposite]
            if value < low:
                value = low
            elif value > high:
                value = high
            levels[m] = value
        # uneven light can push the estimates past each other; an inferred corner
        # needs the same contrast as a seen one
        if lit[m] - dark[m] < 12.0:
            return None
    return _Reference(tuple(lit), tuple(dark))


_SLOT_POINTS = tuple(slot_center(*split_slot(flat)) for flat in range(TOTAL_SLOTS))
_GATES = gate_slots()
_GUARDS = guard_slots()
_GATES_BY_RING = tuple(tuple(s for s in _GATES if split_slot(s)[0] == ring) for ring in range(3))
_GUARDS_BY_RING = tuple(tuple(s for s in _GUARDS if split_slot(s)[0] == ring) for ring in range(3))
_DATA_SLOTS = data_slots()
_DATA_RINGS = tuple(split_slot(slot)[0] for slot in _DATA_SLOTS)


def _normalised_dot(project: Projector, reference: _Reference, flat: int) -> float:
    x, y = _SLOT_POINTS[flat]
    lit, dark = reference.at(x, y)
    return ieee_div(_dot_samples(project, x, y, 3.5) - dark, lit - dark)


def _sequential_sum(values: Sequence[float]) -> float:
    """Left-to-right float sum, as Rust's ``Iterator::sum`` computes it."""
    return reduce(add, values) if values else 0.0


def _gate_score(project: Projector, reference: _Reference) -> float:
    gates = [_normalised_dot(project, reference, s) for s in _GATES]
    guards = [_normalised_dot(project, reference, s) for s in _GUARDS]
    return _sequential_sum(gates) / len(gates) - _sequential_sum(guards) / len(guards)


#: Centres of the lattice cells outside the ``天`` mask (no tile is ever drawn there),
#: row-major.
_EMPTY_CELLS = tuple(
    (TILE_ORIGIN + TILE_PITCH * (col + 0.5), TILE_ORIGIN + TILE_PITCH * (row + 0.5))
    for row, line in enumerate(MASK)
    for col, mark in enumerate(line)
    if mark != "#"
)


def _mask_score(project: Projector, reference: _Reference) -> float:
    """How well the ``天`` lines up: the mean normalised level over the tiles (each sampled
    at five points across the tile, so a glyph stroke at the centre does not decide it)
    minus the mean over the empty lattice cells.

    The mask is symmetric left to right but not top to bottom, so this tells the four
    quarter turns apart even when the ring gates are damaged.
    """

    def level_sum(points: Sequence[Tuple[float, float]]) -> float:
        total = None
        at = reference.at
        for x, y in points:
            lit, dark = at(x, y)
            samples = project(x + 0.0, y + 0.0)
            samples += project(x + 8.0, y + 0.0)
            samples += project(x + -8.0, y + 0.0)
            samples += project(x + 0.0, y + 8.0)
            samples += project(x + 0.0, y + -8.0)
            value = ieee_div(samples / 5.0 - dark, lit - dark)
            total = value if total is None else total + value
        return 0.0 if total is None else total

    tiles = level_sum(_TILE_CENTERS) / TILE_COUNT
    empty = level_sum(_EMPTY_CELLS) / len(_EMPTY_CELLS)
    return tiles - empty


def _canonical_corner(index: int, rotation: int, mirrored: bool) -> int:
    """Canonical index of the corner at index ``index`` of a finder quad under one
    orientation hypothesis."""
    if mirrored:
        return (rotation + 4 - index) % 4
    return (index + 4 - rotation) % 4


#: The five sample points of every ring slot, in flat slot order (``_dot_samples`` with
#: spread 3.5, coordinates computed exactly as there).
_RING_SAMPLES = tuple(
    (x + 0.0, y + 0.0, x + 3.5, y + 0.0, x + -3.5, y + 0.0, x + 0.0, y + 3.5, x + 0.0, y + -3.5)
    for x, y in _SLOT_POINTS
)


def _ring_brightness(image: Luma, corners: Sequence[Tuple[float, float]]) -> Optional[float]:
    """The brightness summed over all ring slots under the pose that maps the canonical
    corners onto ``corners`` (in quad order).

    The slots form the same set of points under every quarter turn and mirror of the
    canvas (80, 92 and 104 are multiples of four), so the value does not depend on the
    orientation.
    """
    h = Homography.from_points(_CANONICAL, corners)
    if h is None:
        return None
    project = _projector(image, h)
    # every sample is at least +0.0 (or NaN), so starting the sum at 0.0, as the
    # reference's `dot_samples` and slot sum do, adds nothing
    total = 0.0
    for ax, ay, bx, by, cx, cy, dx, dy, ex, ey in _RING_SAMPLES:
        samples = project(ax, ay)
        samples += project(bx, by)
        samples += project(cx, cy)
        samples += project(dx, dy)
        samples += project(ex, ey)
        total += samples / 5.0
    return total


def _refine_inferred_corner(
    image: Luma, corners: Sequence[Finder], inferred: int
) -> Tuple[Finder, ...]:
    """Moves an inferred corner to where the three dotted rings line up best.

    A 13 x 13 search in steps of 2 % of the mean leg around the parallelogram estimate,
    then a 9 x 9 search in steps of 0.5 % around the best point. The rings fix the
    geometry only; the orientation is decided afterwards by the gates and the ``天``.
    """
    points = [(f.x, f.y) for f in corners]
    sx, sy = points[inferred]

    def distance(other: int) -> float:
        ex = points[other][0] - sx
        ey = points[other][1] - sy
        return math.sqrt(ex * ex + ey * ey)

    leg = 0.5 * (distance((inferred + 1) % 4) + distance((inferred + 3) % 4))
    best = [-F64_MAX, (sx, sy)]

    def search(centre: Tuple[float, float], step: float, reach: int) -> None:
        cx, cy = centre
        for dy in range(-reach, reach + 1):
            y = cy + dy * step
            for dx in range(-reach, reach + 1):
                candidate = (cx + dx * step, y)
                points[inferred] = candidate
                brightness = _ring_brightness(image, points)
                if brightness is not None and brightness > best[0]:
                    best[0] = brightness
                    best[1] = candidate

    search((sx, sy), 0.02 * leg, 6)
    search(best[1], 0.005 * leg, 4)
    refined = list(corners)
    bx, by = best[1]
    refined[inferred] = Finder(bx, by, corners[inferred].size)
    return tuple(refined)


def _read_dots(project: Projector, reference: _Reference) -> Tuple[bytearray, List[float]]:
    """Read lane ``D``: the transmitted bytes and per-byte confidence."""
    # per-ring thresholds from the gates (lit) and guards (dark)
    thresholds = [0.5] * RING_COUNT
    for ring in range(RING_COUNT):
        lit = [_normalised_dot(project, reference, s) for s in _GATES_BY_RING[ring]]
        dark = [_normalised_dot(project, reference, s) for s in _GUARDS_BY_RING[ring]]
        if lit and dark:
            level_lit = _sequential_sum(lit) / len(lit)
            level_dark = _sequential_sum(dark) / len(dark)
            if level_lit - level_dark > 0.2:
                thresholds[ring] = 0.5 * (level_lit + level_dark)
    word = bytearray(D_WORD)
    confidence = [F64_MAX] * D_WORD
    for bit, slot in enumerate(_DATA_SLOTS):
        value = _normalised_dot(project, reference, slot)
        threshold = thresholds[_DATA_RINGS[bit]]
        if value > threshold:
            word[bit >> 3] |= 1 << (7 - (bit & 7))
        margin = abs(value - threshold)
        if margin < confidence[bit >> 3]:
            confidence[bit >> 3] = margin
    return word, confidence


def _decode_with_erasures(
    lane: Lane, word: bytes, confidence: Sequence[float]
) -> Optional[LaneResult]:
    """Try Reed-Solomon with growing numbers of erasures, least confident first.

    The schedule erases 0, 1/8, 1/4, 1/3 and 1/2 of the parity bytes, and for lane ``K`` also
    2/3. Lanes ``D`` and ``P`` stop at 1/2: their words have only 11 and 13 parity bytes, and a
    further erasure step leaves so few spare ones that it accepts wrong codewords (lane ``D``
    at 7 erasures: about 0.4 % of random words, and 5 wrong lanes in 2 900 simulated harsh
    frames; lane ``P`` at 8: 2 wrong lanes in 600 banded 480p frames). Capping them costs
    0.65 % of the lane ``D`` reads and 0.15 % of the lane ``P`` reads in those frames.
    """
    nsym = lane.parity_len
    order = sorted(range(len(word)), key=lambda i: total_key(confidence[i]))
    counts = [0, nsym // 8, nsym // 4, nsym // 3, nsym // 2]
    if lane is Lane.K:
        counts.append(nsym * 2 // 3)
    schedule = []
    for count in counts:
        if not schedule or schedule[-1] != count:
            schedule.append(count)
    for erasures in schedule:
        positions = order[:erasures]
        trial = bytearray(word)
        # zero the erased bytes so stale values cannot leak through
        for p in positions:
            trial[p] = 0
        try:
            data, corrected = decode_lane_counted(lane, trial, positions)
        except RsError:
            continue
        return LaneResult(data=data, corrected=corrected, erasures=len(positions))
    return None


def _read_lane_d(project: Projector, reference: _Reference) -> Optional[LaneResult]:
    """Lane ``D`` under one pose."""
    word, confidence = _read_dots(project, reference)
    return _decode_with_erasures(Lane.D, word, confidence)


_PATTERNS: Dict[float, Tuple[Tuple[float, ...], ...]] = {}


def _build_patterns(sigma: float) -> Tuple[Tuple[float, ...], ...]:
    """``pred[b * 16 + g]``: expected normalised patch for polarity ``b``, glyph ``g``."""
    cached = _PATTERNS.get(sigma)
    if cached is not None:
        return cached
    raw = []
    for i in range(-2, 3):
        if sigma < 0.05:
            raw.append(1.0 if i == 0 else 0.0)
        else:
            raw.append(math.exp(-(float(i) * float(i)) / (2.0 * sigma * sigma)))
    total = _sequential_sum(raw)
    kernel = [v / total for v in raw]
    pred = []
    for polarity in range(2):
        for template in TEMPLATES:
            coverage = [c / 255.0 for c in template]
            blurred = [0.0] * _CELLS
            for v in range(_PATCH):
                for u in range(_PATCH):
                    acc = 0.0
                    for ky, wy in enumerate(kernel):
                        sy = v + ky - 2
                        if not 0 <= sy < _PATCH:
                            continue
                        for kx, wx in enumerate(kernel):
                            sx = u + kx - 2
                            if 0 <= sx < _PATCH:
                                acc += wx * wy * coverage[sy * _PATCH + sx]
                    blurred[v * _PATCH + u] = acc
            if polarity == 1:
                pattern = tuple(1.0 - (1.0 - INK_ON_LIGHT) * ink for ink in blurred)
            else:
                pattern = tuple(PINK_ON_DARK * ink for ink in blurred)
            pred.append(pattern)
    patterns = tuple(pred)
    if sigma == sigma:
        _PATTERNS[sigma] = patterns
    return patterns


class _TileRead:
    __slots__ = ("light", "glyph", "polarity_margin", "glyph_margin", "error")

    def __init__(
        self, light: bool, glyph: int, polarity_margin: float, glyph_margin: float, error: float
    ) -> None:
        self.light = light
        self.glyph = glyph
        self.polarity_margin = polarity_margin
        self.glyph_margin = glyph_margin
        self.error = error


_HALF_BOX = GLYPH_BOX / 2.0
_CELL = GLYPH_BOX / _PATCH
_QUARTER = ((-0.25, -0.25), (0.25, -0.25), (-0.25, 0.25), (0.25, 0.25))
_TILE_CENTERS = tuple(tile_center(t) for t in range(TILE_COUNT))
_NOT_ERASED = (False,) * TILE_COUNT


def _sample_patches(project: Projector) -> List[List[float]]:
    """The raw 8x8 luma patch of every tile, as captured (no reference levels applied).

    ``patches[tile][v * 8 + u]`` is the mean of four bilinear samples at +-1/4 cell.
    """
    cell = _CELL
    half = _HALF_BOX
    offsets = tuple((ox * cell, oy * cell) for ox, oy in _QUARTER)
    (ax, ay), (bx, by), (cx_, cy_), (dx, dy) = offsets
    patches: List[List[float]] = []
    for cx, cy in _TILE_CENTERS:
        patch: List[float] = []
        for v in range(_PATCH):
            gy = cy - half + (v + 0.5) * cell
            for u in range(_PATCH):
                gx = cx - half + (u + 0.5) * cell
                total = project(gx + ax, gy + ay)
                total += project(gx + bx, gy + by)
                total += project(gx + cx_, gy + cy_)
                total += project(gx + dx, gy + dy)
                patch.append(total / 4.0)
        patches.append(patch)
    return patches


def _sorted_total(values: Sequence[float]) -> List[float]:
    """``values`` ascending in Rust's ``f64::total_cmp`` order."""
    total = sum(values)
    if total == total:
        # no NaN: the plain order is the total order (zeros of either sign tie, which no
        # result below can tell apart)
        return sorted(values)
    return sorted(values, key=total_key)


def _patch_levels(values: Sequence[float]) -> Tuple[float, float]:
    """The robust darkest and brightest level of a patch: the values ``_PATCH_CUT`` cells in
    from either end of the sorted cells."""
    ordered = _sorted_total(values)
    return ordered[_PATCH_CUT], ordered[_CELLS - 1 - _PATCH_CUT]


def _apply_levels(values: Sequence[float], low: float, high: float, floor: float) -> List[float]:
    """``values`` with ``low`` mapped to 0 and ``high`` to 1, clamped to [-0.25, 1.25]."""
    span = high - low
    if not span > floor:  # `f64::max`: a NaN span yields the floor
        span = floor
    out = []
    for value in values:
        level = (value - low) / span
        if level < -0.25:  # `f64::clamp`: NaN passes through
            level = -0.25
        elif level > 1.25:
            level = 1.25
        out.append(level)
    return out


def _rescale(values: Sequence[float], floor: float) -> List[float]:
    """Maps a patch's own darkest level to 0 and brightest to 1, with ``floor`` as the smallest
    span that counts as contrast."""
    low, high = _patch_levels(values)
    return _apply_levels(values, low, high, floor)


_RESCALED_PATTERNS: Dict[float, Tuple[Tuple[float, ...], ...]] = {}


def _rescaled_patterns(sigma: float) -> Tuple[Tuple[float, ...], ...]:
    """The templates of ``sigma`` rescaled like the patches of the normalised read."""
    cached = _RESCALED_PATTERNS.get(sigma)
    if cached is not None:
        return cached
    patterns = tuple(tuple(_rescale(pattern, 0.001)) for pattern in _build_patterns(sigma))
    if sigma == sigma:
        _RESCALED_PATTERNS[sigma] = patterns
    return patterns


def _classify(
    patches: Sequence[Sequence[float]],
    sigmas: Sequence[float],
    rescale_templates: bool,
    erased: Sequence[bool],
) -> List[_TileRead]:
    """Picks for every patch the polarity and glyph whose template matches best.

    The template blur is chosen per frame, by the lowest total error. With
    ``rescale_templates`` the templates are rescaled like the patches; tiles flagged in
    ``erased`` get zero margins, so they are the first the Reed-Solomon decoder treats as
    erasures.
    """
    best_total = F64_MAX
    best_reads: List[_TileRead] = []
    tiles = len(patches)
    if tiles == 0:
        return best_reads
    # cell-major, so that one cell of every tile is compared at a time
    cells = list(zip(*patches))
    for sigma in sigmas:
        pred = _rescaled_patterns(sigma) if rescale_templates else _build_patterns(sigma)
        # errors[h * tiles + t] accumulates sum_c (patch[t][c] - pred[h][c])^2
        # over c in order, exactly like the reference's per-tile fold.
        errors: Optional[List[float]] = None
        for c in range(_CELLS):
            observed = cells[c] * _HYPOTHESES
            expected: List[float] = []
            for h in range(_HYPOTHESES):
                expected += [pred[h][c]] * tiles
            diff = list(map(sub, observed, expected))
            squares = map(mul, diff, diff)
            errors = list(squares) if errors is None else list(map(add, errors, squares))
        assert errors is not None
        total = 0.0
        reads = []
        hypotheses = range(_HYPOTHESES)
        for tile in range(tiles):
            row = errors[tile::tiles]
            best = min(hypotheses, key=row.__getitem__)
            polarity = best // GLYPH_COUNT
            glyph = best % GLYPH_COUNT
            error = row[best]
            other = F64_MAX
            start = (1 - polarity) * GLYPH_COUNT
            for value in row[start : start + GLYPH_COUNT]:
                if value < other:
                    other = value
            other_glyph = F64_MAX
            start = polarity * GLYPH_COUNT
            for g in range(GLYPH_COUNT):
                if g != glyph:
                    value = row[start + g]
                    if value < other_glyph:
                        other_glyph = value
            total += error
            if erased[tile]:
                reads.append(_TileRead(polarity == 1, glyph, 0.0, 0.0, error))
            else:
                reads.append(
                    _TileRead(polarity == 1, glyph, other - error, other_glyph - error, error)
                )
        if total < best_total:
            best_total = total
            best_reads = reads
    return best_reads


def _read_tiles(
    patches: Sequence[Sequence[float]], reference: _Reference, sigmas: Sequence[float]
) -> List[_TileRead]:
    """The level read: every patch is judged against the light and dark levels measured at
    the finders, interpolated to the tile."""
    levelled = []
    for raw, (cx, cy) in zip(patches, _TILE_CENTERS):
        lit, dark = reference.at(cx, cy)
        scale = lit - dark
        if scale != 0.0:
            levelled.append([(value - dark) / scale for value in raw])
        else:
            levelled.append([ieee_div(value - dark, scale) for value in raw])
    return _classify(levelled, sigmas, False, _NOT_ERASED)


@dataclass(frozen=True)
class _TileEvidence:
    """Raw canonical tile patches and finder levels from one decoded capture."""

    patches: Sequence[Sequence[float]]
    reference: _Reference


def _tile_evidence(
    image: Luma, frame: DecodedFrame, options: DecodeOptions
) -> Optional[_TileEvidence]:
    """Sample a usable capture under its independently decoded canonical pose."""
    if not _supported(image, options) or (
        frame.inferred_corner is not None and not 0 <= frame.inferred_corner <= 3
    ):
        return None
    project = _projector(image, frame.homography)
    reference = _reference_levels(project, frame.inferred_corner)
    if reference is None:
        return None
    return _TileEvidence(_sample_patches(project), reference)


def _levelled_patches(
    patches: Sequence[Sequence[float]], reference: _Reference
) -> List[List[float]]:
    """Level each capture by its own finders before averaging its samples."""
    levelled = []
    for raw, (cx, cy) in zip(patches, _TILE_CENTERS):
        lit, dark = reference.at(cx, cy)
        levelled.append([ieee_div(value - dark, lit - dark) for value in raw])
    return levelled


def _mean_patches(sets: Sequence[Sequence[Sequence[float]]]) -> List[List[float]]:
    """Cell-by-cell mean, summed in capture order like the Rust reference."""
    mean = [[0.0] * _CELLS for _ in range(TILE_COUNT)]
    for patches in sets:
        for total, patch in zip(mean, patches):
            for cell, value in enumerate(patch):
                total[cell] += value
    count = float(len(sets))
    return [[value / count for value in patch] for patch in mean]


def _merge_tiles(
    evidence: Sequence[_TileEvidence], options: DecodeOptions
) -> Tuple[Optional[LaneResult], Optional[LaneResult]]:
    """Decode averaged tile lanes; the caller must check their shown-frame headers."""
    if not evidence:
        return None, None
    levelled = _mean_patches([_levelled_patches(e.patches, e.reference) for e in evidence])
    reads = _classify(levelled, options.template_sigmas, False, _NOT_ERASED)
    (p_word, p_conf), (k_word, k_conf) = _tile_words(reads)
    p = _decode_with_erasures(Lane.P, p_word, p_conf)
    k = _decode_with_erasures(Lane.K, k_word, k_conf)
    if p is None or k is None:
        raw = _mean_patches([e.patches for e in evidence])
        reads = _read_tiles_normalised(raw, options.template_sigmas)
        (p_word, p_conf), (k_word, k_conf) = _tile_words(reads)
        if p is None:
            p = _decode_with_erasures(Lane.P, p_word, p_conf)
        if k is None:
            k = _decode_with_erasures(Lane.K, k_word, k_conf)
    return p, k


def _read_tiles_normalised(
    patches: Sequence[Sequence[float]], sigmas: Sequence[float]
) -> List[_TileRead]:
    """The normalised read: every patch and every template is rescaled by its own contrast
    before they are compared, so the judgement does not depend on absolute levels."""
    levels = [_patch_levels(raw) for raw in patches]
    spans = [high - low for low, high in levels]
    median = _sorted_total(spans)[TILE_COUNT // 2]
    weak = _WEAK_TILE * median
    erased = [span < weak for span in spans]
    # `_rescale(raw, 1.0)` with the levels found above (the same sort, done once)
    scaled = [_apply_levels(raw, low, high, 1.0) for raw, (low, high) in zip(patches, levels)]
    return _classify(scaled, sigmas, True, erased)


WordConfidence = Tuple[bytearray, List[float]]


def _tile_words(reads: Sequence[_TileRead]) -> Tuple[WordConfidence, WordConfidence]:
    p = bytearray(P_WORD)
    p_conf = [F64_MAX] * P_WORD
    k = bytearray(K_WORD)
    k_conf = [F64_MAX] * K_WORD
    for tile, read in enumerate(reads):
        if read.light:
            p[tile >> 3] |= 1 << (7 - (tile & 7))
        p_conf[tile >> 3] = f64_min(p_conf[tile >> 3], read.polarity_margin)
        k[tile >> 1] |= read.glyph << 4 if tile % 2 == 0 else read.glyph
        k_conf[tile >> 1] = f64_min(
            k_conf[tile >> 1], f64_min(read.glyph_margin, read.polarity_margin)
        )
    return (p, p_conf), (k, k_conf)


def _read_tile_lanes(
    patches: Sequence[Sequence[float]], reference: _Reference, sigmas: Sequence[float]
) -> Tuple[Optional[LaneResult], Optional[LaneResult]]:
    """Lanes ``P`` and ``K`` from one set of patches: the level read first, then, for any
    lane still unreadable, the normalised read."""
    reads = _read_tiles(patches, reference, sigmas)
    (p_word, p_conf), (k_word, k_conf) = _tile_words(reads)
    p = _decode_with_erasures(Lane.P, p_word, p_conf)
    k = _decode_with_erasures(Lane.K, k_word, k_conf)
    if p is None or k is None:
        reads = _read_tiles_normalised(patches, sigmas)
        (p_word, p_conf), (k_word, k_conf) = _tile_words(reads)
        if p is None:
            p = _decode_with_erasures(Lane.P, p_word, p_conf)
        if k is None:
            k = _decode_with_erasures(Lane.K, k_word, k_conf)
    return p, k


_CANONICAL = tuple((float(x), float(y)) for x, y in FINDER_CENTERS)


def _hypotheses(
    finders: Sequence[Finder], try_mirrored: bool
) -> List[Tuple[int, bool, Homography]]:
    out = []
    for mirrored in (False, True):
        if mirrored and not try_mirrored:
            continue
        for rotation in range(4):
            dst = []
            for i in range(4):
                q = finders[(rotation + 4 - i) % 4] if mirrored else finders[(i + rotation) % 4]
                dst.append((q.x, q.y))
            h = Homography.from_points(_CANONICAL, dst)
            if h is not None:
                out.append((rotation, mirrored, h))
    return out


def _supported(image: Luma, options: DecodeOptions) -> bool:
    return (
        image.width >= 48
        and image.height >= 48
        and image.width * image.height <= options.max_pixels
        and len(image.data) == image.width * image.height
    )


def _finish(
    project: Projector,
    options: DecodeOptions,
    rotation: int,
    mirrored: bool,
    h: Homography,
    reference: _Reference,
    d: Optional[LaneResult],
) -> DecodedFrame:
    if d is None:
        d = _read_lane_d(project, reference)
    patches = _sample_patches(project)
    p, k = _read_tile_lanes(patches, reference, options.template_sigmas)
    return DecodedFrame(homography=h, rotation=rotation, mirrored=mirrored, p=p, k=k, d=d)


def _decode(image: Luma, options: DecodeOptions) -> DecodedFrame:
    if not _supported(image, options):
        raise DecodeError(DecodeErrorKind.UNSUPPORTED_IMAGE)
    located = False
    for finder_set in candidates(image):
        located = True
        frame = _decode_candidate(image, options, finder_set)
        if frame is not None:
            return frame
    raise DecodeError(DecodeErrorKind.NO_ORIENTATION if located else DecodeErrorKind.NO_FINDERS)


def _decode_candidate(
    image: Luma, options: DecodeOptions, finder_set: FinderSet
) -> Optional[DecodedFrame]:
    """One candidate finder set: orientation hypotheses ranked by gate score + ``天``
    score; lane ``D`` under the best three whose gate score is at least 0.2, then the tile
    lanes under the best four."""
    index = finder_set.inferred
    corners = finder_set.corners
    if index is not None:
        corners = _refine_inferred_corner(image, corners, index)
    scored = []
    for rotation, mirrored, h in _hypotheses(corners, options.try_mirrored):
        inferred = None if index is None else _canonical_corner(index, rotation, mirrored)
        project = _projector(image, h)
        reference = _reference_levels(project, inferred)
        if reference is None:
            continue
        gate = _gate_score(project, reference)
        mask = _mask_score(project, reference)
        scored.append((gate, mask, rotation, mirrored, h, reference, project, inferred))
    # stable sort, highest score first (Rust: `(b.0 + b.1).total_cmp(&(a.0 + a.1))`)
    scored.sort(key=lambda entry: total_key(entry[0] + entry[1]), reverse=True)
    # 1. the ring beacon is the cheapest and strongest orientation check (the order is by
    #    gate + `天` score, so a weak gate further down does not end the search)
    for gate, _, rotation, mirrored, h, reference, project, inferred in scored[:3]:
        if gate < 0.2:
            continue
        d = _read_lane_d(project, reference)
        if d is not None:
            frame = _finish(project, options, rotation, mirrored, h, reference, d)
            return replace(frame, inferred_corner=inferred)
    # 2. fall back to the tile lanes under the most promising orientations
    for _, _, rotation, mirrored, h, reference, project, inferred in scored[:4]:
        patches = _sample_patches(project)
        p, k = _read_tile_lanes(patches, reference, options.template_sigmas)
        if p is not None or k is not None:
            return DecodedFrame(
                homography=h,
                rotation=rotation,
                mirrored=mirrored,
                p=p,
                k=k,
                d=_read_lane_d(project, reference),
                inferred_corner=inferred,
            )
    return None


def _track(image: Luma, previous: DecodedFrame, options: DecodeOptions) -> Optional[DecodedFrame]:
    corner = previous.inferred_corner
    # a frame built by the caller may name a corner that does not exist
    if not _supported(image, options) or (corner is not None and not 0 <= corner <= 3):
        return None
    h0 = previous.homography
    apply = h0.apply
    expected = []
    for cx, cy in FINDER_CENTERS:
        x, y = apply(cx, cy)
        ax, ay = apply(cx - 60.0, cy)
        bx, by = apply(cx + 60.0, cy)
        across = math.sqrt((ax - bx) * (ax - bx) + (ay - by) * (ay - by))
        ax, ay = apply(cx, cy - 60.0)
        bx, by = apply(cx, cy + 60.0)
        down = math.sqrt((ax - bx) * (ax - bx) + (ay - by) * (ay - by))
        expected.append(Finder(x, y, f64_max(across, down)))
    short = float(min(image.width, image.height))
    isfinite = math.isfinite
    for f in expected:
        if not (isfinite(f.x) and isfinite(f.y) and isfinite(f.size)) or f.size > short:
            return None
    previously_inferred = previous.inferred_corner
    found: List[Optional[Finder]] = [
        None if i == previously_inferred else follow(image, e) for i, e in enumerate(expected)
    ]
    # the mean movement of the corners that were followed predicts the others
    moved = [(f.x - e.x, f.y - e.y) for f, e in zip(found, expected) if f is not None]
    if len(moved) < 3:
        return None
    shift_x = _sequential_sum([m[0] for m in moved]) / len(moved)
    shift_y = _sequential_sum([m[1] for m in moved]) / len(moved)

    def predicted(i: int) -> Finder:
        e = expected[i]
        return Finder(e.x + shift_x, e.y + shift_y, e.size)

    # a corner that was hidden is seen again only when its blossom is found right where the
    # others say it is (a bright thumb beside it must not count)
    if previously_inferred is not None:
        at = predicted(previously_inferred)
        again = follow(image, at)
        if again is not None:
            ex = again.x - at.x
            ey = again.y - at.y
            if not math.sqrt(ex * ex + ey * ey) <= 0.25 * at.size:
                again = None
        found[previously_inferred] = again
    lost = [i for i in range(4) if found[i] is None]
    inferred: Optional[int] = None
    if len(lost) == 1:
        inferred = lost[0]
        found[inferred] = predicted(inferred)
    elif lost:
        return None
    corners: Tuple[Finder, ...] = tuple(f for f in found if f is not None)
    if inferred is not None:
        corners = _refine_inferred_corner(image, corners, inferred)
    h = Homography.from_points(_CANONICAL, [(f.x, f.y) for f in corners])
    if h is None:
        return None
    project = _projector(image, h)
    reference = _reference_levels(project, inferred)
    if reference is None:
        return None
    d = _read_lane_d(project, reference)
    patches = _sample_patches(project)
    p, k = _read_tile_lanes(patches, reference, options.template_sigmas)
    if p is None and k is None and d is None:
        return None
    return DecodedFrame(
        homography=h,
        rotation=previous.rotation,
        mirrored=previous.mirrored,
        p=p,
        k=k,
        d=d,
        inferred_corner=inferred,
    )


def _scale(h: Homography, factor: int) -> Homography:
    f = float(factor)
    return Homography((f, 0.0, 0.0, 0.0, f, 0.0, 0.0, 0.0, 1.0)).compose(h)


def _downscale_factor(image: Luma, max_side: Optional[int]) -> int:
    if max_side is None:
        return 1
    if max_side < 48:
        raise ValueError("max_side must be at least 48 pixels")
    side = max(image.width, image.height)
    return max(1, -(-side // max_side))


def decode_frame(
    image: Luma, options: Optional[DecodeOptions] = None, *, max_side: Optional[int] = None
) -> DecodedFrame:
    """Decode one camera frame.

    Tries the finder candidates of :func:`iroha_petal.locate.candidates` in order
    and returns the first that reads. For each, the orientation hypotheses (four
    quarter turns, optionally mirrored) are ranked by the ring gates plus the
    ``天``; lane ``D`` is tried under the best three whose gate score is at least
    0.2, then the tile lanes under the best four. A candidate with a hidden
    corner blossom reports it in :attr:`DecodedFrame.inferred_corner`.

    Raises :class:`DecodeError` with :attr:`DecodeErrorKind.UNSUPPORTED_IMAGE`
    for unusable images, :attr:`DecodeErrorKind.NO_FINDERS` when no code is
    visible and :attr:`DecodeErrorKind.NO_ORIENTATION` when no orientation
    yields a readable lane.

    ``max_side`` (off by default) first box-filters images whose longer side
    exceeds it by the smallest integer factor that fits; the returned
    homography still maps into the original image's pixel coordinates.
    """
    if options is None:
        options = DecodeOptions()
    factor = _downscale_factor(image, max_side)
    if factor == 1:
        return _decode(image, options)
    frame = _decode(image.downscaled(factor), options)
    return replace(frame, homography=_scale(frame.homography, factor))


def track_frame(
    image: Luma, previous: DecodedFrame, options: Optional[DecodeOptions] = None
) -> Optional[DecodedFrame]:
    """Follow a code from the previous frame that decoded, without searching the whole
    image for finders (the most expensive part of :func:`decode_frame`).

    Each corner finder seen in the previous frame is re-found near where the previous
    pose puts it (see :func:`iroha_petal.locate.follow`); the mean movement of those
    predicts the rest. A corner inferred in the previous frame counts as seen again only
    when its blossom is re-found within a quarter diameter of that prediction (so a thumb
    beside it does not count). When exactly one corner is missing it is placed at the
    prediction and refined against the rings like an inferred corner. The orientation is
    kept from the previous frame. Returns ``None`` when the image is unusable, the
    previous pose is broken, two corners are lost or no lane decodes; the caller then
    runs :func:`decode_frame`.

    ``previous.homography`` must map into the pixel coordinates of ``image``.
    """
    if options is None:
        options = DecodeOptions()
    return _track(image, previous, options)


def decode_frame_at(
    image: Luma, homography: Homography, options: Optional[DecodeOptions] = None
) -> Optional[DecodedFrame]:
    """Read all lanes with a known canvas-to-pixel homography (no finder search).

    Returns ``None`` when the image is unusable (see
    :attr:`DecodeErrorKind.UNSUPPORTED_IMAGE`) or the finder reference levels
    are too weak. Used by trackers that already know the pose, by refinement
    passes and by qualification tooling with a ground-truth pose.
    """
    if options is None:
        options = DecodeOptions()
    if not _supported(image, options):
        return None
    project = _projector(image, homography)
    reference = _reference_levels(project)
    if reference is None:
        return None
    return _finish(project, options, 0, False, homography, reference, None)


def observed_cells(
    image: Luma, frame: DecodedFrame, options: Optional[DecodeOptions] = None
) -> Optional[FrameCells]:
    """Build the cells a decoder believes it saw, for diagnostics.

    Tiles are taken from the level read (the one that judges against the finder levels),
    even for a frame whose lanes were rescued by the normalised read.
    """
    if options is None:
        options = DecodeOptions()
    if not _supported(image, options):
        return None
    project = _projector(image, frame.homography)
    reference = _reference_levels(project, frame.inferred_corner)
    if reference is None:
        return None
    patches = _sample_patches(project)
    reads = _read_tiles(patches, reference, options.template_sigmas)
    (p, _), (k, _) = _tile_words(reads)
    d, _ = _read_dots(project, reference)
    return FrameCells.from_words(bytes(p), bytes(k), bytes(d))


def tile_match_error(
    image: Luma, frame: DecodedFrame, options: Optional[DecodeOptions] = None
) -> Optional[float]:
    """Mean squared tile-match error of the level read, a quick image-quality indicator.

    It can be large for a frame whose lanes were rescued by the normalised read, which is
    the point: the finder levels did not describe that picture.
    """
    if options is None:
        options = DecodeOptions()
    if not _supported(image, options):
        return None
    project = _projector(image, frame.homography)
    reference = _reference_levels(project, frame.inferred_corner)
    if reference is None:
        return None
    patches = _sample_patches(project)
    reads = _read_tiles(patches, reference, options.template_sigmas)
    if not reads:
        return NAN
    return _sequential_sum([r.error for r in reads]) / len(reads)
