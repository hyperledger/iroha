//! From a camera luma plane to lane data.
//!
//! The decoder locates the corner finders (four, or three with the fourth
//! inferred), derives a homography for each orientation hypothesis, ranks the
//! orientations by how well the ring gates and the `天` line up (lane `D` must
//! check out), then reads the tiles and dots. Every
//! tile is classified *jointly*: the 8×8 sample patch is compared against the
//! 32 hypotheses (polarity × glyph) and the best match wins, so the katakana
//! and the light/dark bit help each other. Cells the decoder is unsure about
//! become Reed–Solomon erasures.
//!
//! The tile *level read* judges every patch against the light and dark levels
//! measured at the finders. When it leaves lane `P` or `K` unreadable, the
//! *normalised read* is tried: it rescales each patch (and each template) by
//! its own contrast, so over-exposure, veiling light, glare, shadows and
//! gradients cancel out.
//!
//! A camera sees each shown frame three or four times. [`tile_evidence`] keeps
//! what one capture shows of the tile field, and [`merge_tiles`] reads lanes
//! `P` and `K` from the average of several captures of one shown frame, which
//! recovers lanes that noise, display banding or hand shake cost each capture
//! alone.

use std::sync::OnceLock;

use crate::geometry::Homography;
use crate::glyphs::{GLYPH_COUNT, TEMPLATE_N, TEMPLATES};
use crate::image::Luma;
use crate::lanes::{D_WORD, FrameCells, K_WORD, Lane, P_WORD, decode_lane_counted};
use crate::layout::{
    D_BITS, DOT_RADIUS, FINDER_CENTERS, GLYPH_BOX, MASK, RING_COUNT, SlotRole, TILE_COUNT,
    TILE_ORIGIN, TILE_PITCH, TOTAL_SLOTS, data_slots, ring_offset, slot_center, slot_roles,
    split_slot, tile_center,
};
use crate::locate::{Finder, FinderSet, candidates, follow};
use crate::stream::{AtomPacket, Beacon, DLane, StreamAssembler, parse_atom_lane, parse_d_lane};

const PATCH: usize = TEMPLATE_N;
const CELLS: usize = PATCH * PATCH;
/// Relative level of the glyph ink on a light tile (ink / light fill).
const INK_ON_LIGHT: f64 = 0.04;
/// Relative level of a pink glyph on a dark tile (pink / light fill).
const PINK_ON_DARK: f64 = 0.83;
/// Cells cut from each end of a sorted patch to find its robust darkest and brightest level.
const PATCH_CUT: usize = CELLS / 10;
/// Tiles whose contrast is below this fraction of the median tile contrast become erasures
/// in the normalised read.
const WEAK_TILE: f64 = 0.25;

/// Decoder tuning.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DecodeOptions {
    /// Also try horizontally mirrored images (front-camera previews).
    pub try_mirrored: bool,
    /// Blur widths (in template cells) tried for glyph matching.
    pub template_sigmas: [f64; 5],
    /// Largest image (in pixels) the decoder accepts; larger frames should be
    /// downscaled by the caller. Bounds memory and work on hostile input.
    pub max_pixels: usize,
}

impl Default for DecodeOptions {
    fn default() -> Self {
        Self {
            try_mirrored: true,
            template_sigmas: [0.0, 0.5, 0.8, 1.1, 1.5],
            max_pixels: 12_000_000,
        }
    }
}

/// A lane that passed its Reed–Solomon check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaneResult {
    /// Lane data bytes (header and atoms, or the beacon).
    pub data: Vec<u8>,
    /// Byte positions the Reed–Solomon decoder rewrote: the erased bytes plus
    /// any errors it found among the others (a measure of how close the lane
    /// was to failing).
    pub corrected: usize,
    /// Bytes that were passed to the decoder as erasures.
    pub erasures: usize,
}

/// Everything read from one camera frame.
#[derive(Debug, Clone, PartialEq)]
pub struct DecodedFrame {
    /// Canvas-to-pixel homography that was used.
    pub homography: Homography,
    /// Orientation: how many quarter turns the code is rotated.
    pub rotation: u8,
    /// Whether the image was mirrored.
    pub mirrored: bool,
    /// Lane `P` result.
    pub p: Option<LaneResult>,
    /// Lane `K` result.
    pub k: Option<LaneResult>,
    /// Lane `D` result.
    pub d: Option<LaneResult>,
    /// The corner finder that was hidden (by a finger, a glare or the edge of the
    /// frame) and inferred from the other three, as its canonical index: 0 top-left,
    /// 1 top-right, 2 bottom-right, 3 bottom-left of the upright code.
    pub inferred_corner: Option<u8>,
}

impl DecodedFrame {
    /// Number of lanes that decoded.
    #[must_use]
    pub fn lanes_ok(&self) -> usize {
        usize::from(self.p.is_some())
            + usize::from(self.k.is_some())
            + usize::from(self.d.is_some())
    }

    /// What lane `D` carried, when it decoded.
    #[must_use]
    pub fn d_lane(&self) -> Option<DLane> {
        self.d.as_ref().and_then(|lane| parse_d_lane(&lane.data))
    }

    /// The beacon, when lane `D` decoded on a beacon frame.
    #[must_use]
    pub fn beacon(&self) -> Option<Beacon> {
        match self.d_lane()? {
            DLane::Beacon(beacon) => Some(beacon),
            DLane::Atoms(_) => None,
        }
    }

    /// Atom packets from every lane that decoded.
    #[must_use]
    pub fn atom_packets(&self) -> Vec<AtomPacket> {
        let mut packets: Vec<AtomPacket> = [(Lane::P, &self.p), (Lane::K, &self.k)]
            .into_iter()
            .filter_map(|(lane, result)| {
                result.as_ref().and_then(|r| parse_atom_lane(lane, &r.data))
            })
            .collect();
        if let Some(DLane::Atoms(packet)) = self.d_lane() {
            packets.push(packet);
        }
        packets
    }

    /// Offers everything this frame carries to `assembler`.
    pub fn feed(&self, assembler: &mut StreamAssembler) {
        if let Some(lane) = self.d_lane() {
            assembler.push_d_lane(&lane);
        }
        for (lane, result) in [(Lane::P, &self.p), (Lane::K, &self.k)] {
            if let Some(packet) = result.as_ref().and_then(|r| parse_atom_lane(lane, &r.data)) {
                assembler.push_atoms(&packet);
            }
        }
    }
}

/// Why a frame could not be decoded at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// The image is empty, smaller than 48 pixels on a side, or larger than
    /// [`DecodeOptions::max_pixels`].
    UnsupportedImage,
    /// No set of corner finders (four, or three forming a corner) was found.
    NoFinders,
    /// Finders were found but no orientation produced a readable lane.
    NoOrientation,
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedImage => f.write_str("petal image has an unsupported size"),
            Self::NoFinders => f.write_str("petal finders not found"),
            Self::NoOrientation => f.write_str("no petal orientation produced a readable lane"),
        }
    }
}

impl std::error::Error for DecodeError {}

#[derive(Debug, Clone, Copy, PartialEq)]
struct Reference {
    lit: [f64; 4],
    dark: [f64; 4],
}

impl Reference {
    /// Bilinear interpolation over the canvas of the four corner estimates.
    fn at(&self, x: f64, y: f64) -> (f64, f64) {
        let (u, v) = ((x / 1024.0).clamp(0.0, 1.0), (y / 1024.0).clamp(0.0, 1.0));
        let mix = |c: &[f64; 4]| {
            let top = c[0] * (1.0 - u) + c[1] * u;
            let bottom = c[3] * (1.0 - u) + c[2] * u;
            top * (1.0 - v) + bottom * v
        };
        (mix(&self.lit), mix(&self.dark))
    }
}

fn dot_samples(image: &Luma, h: &Homography, x: f64, y: f64, spread: f64) -> f64 {
    let mut sum = 0.0;
    for (dx, dy) in [
        (0.0, 0.0),
        (spread, 0.0),
        (-spread, 0.0),
        (0.0, spread),
        (0.0, -spread),
    ] {
        let (px, py) = h.apply(x + dx, y + dy);
        sum += image.sample(px, py);
    }
    sum / 5.0
}

/// Light and dark levels at the four corners: the solid blossom core, and the
/// black canvas 100 units inward of it. An `inferred` corner (canonical index)
/// was not seen, so its levels are extrapolated from the other three by the
/// parallelogram rule and kept within their range.
fn reference_levels(image: &Luma, h: &Homography, inferred: Option<usize>) -> Option<Reference> {
    let mut lit = [0.0; 4];
    let mut dark = [0.0; 4];
    for (i, &(cx, cy)) in FINDER_CENTERS.iter().enumerate() {
        if inferred == Some(i) {
            continue;
        }
        let (cx, cy) = (f64::from(cx), f64::from(cy));
        // the blossom is solid out to radius 24 around its centre
        let (px, py) = h.apply(cx, cy);
        let mut sum = image.sample(px, py);
        for k in 0..8 {
            let angle = core::f64::consts::TAU * f64::from(k) / 8.0;
            let (px, py) = h.apply(cx + 20.0 * angle.cos(), cy + 20.0 * angle.sin());
            sum += image.sample(px, py);
        }
        lit[i] = sum / 9.0;
        let (sx, sy) = (
            if cx < 512.0 { 1.0 } else { -1.0 },
            if cy < 512.0 { 1.0 } else { -1.0 },
        );
        let a = dot_samples(image, h, cx + sx * 100.0, cy, 5.0);
        let b = dot_samples(image, h, cx, cy + sy * 100.0, 5.0);
        dark[i] = 0.5 * (a + b);
        // also refuses NaN levels, which only a non-finite pose can produce
        if !(lit[i] - dark[i]).is_finite() || lit[i] - dark[i] < 12.0 {
            return None;
        }
    }
    if let Some(m) = inferred {
        let (n1, opposite, n2) = ((m + 1) % 4, (m + 2) % 4, (m + 3) % 4);
        let extrapolate = |v: &[f64; 4]| {
            let low = v[n1].min(v[opposite]).min(v[n2]);
            let high = v[n1].max(v[opposite]).max(v[n2]);
            (v[n1] + v[n2] - v[opposite]).clamp(low, high)
        };
        lit[m] = extrapolate(&lit);
        dark[m] = extrapolate(&dark);
        // uneven light can push the estimates past each other; an inferred corner
        // needs the same contrast as a seen one
        if lit[m] - dark[m] < 12.0 {
            return None;
        }
    }
    Some(Reference { lit, dark })
}

/// Centres of the lattice cells outside the `天` mask (no tile is ever drawn there).
fn empty_cells() -> &'static Vec<(f64, f64)> {
    static CELLS: OnceLock<Vec<(f64, f64)>> = OnceLock::new();
    CELLS.get_or_init(|| {
        let mut cells = Vec::new();
        for (row, line) in MASK.iter().enumerate() {
            for (col, mark) in line.bytes().enumerate() {
                if mark != b'#' {
                    cells.push((
                        f64::from(TILE_ORIGIN) + f64::from(TILE_PITCH) * (col as f64 + 0.5),
                        f64::from(TILE_ORIGIN) + f64::from(TILE_PITCH) * (row as f64 + 0.5),
                    ));
                }
            }
        }
        cells
    })
}

/// How well the `天` lines up: the mean normalised level over the tiles (each
/// sampled at five points across the tile, so a glyph stroke at the centre does
/// not decide it) minus the mean over the empty lattice cells. The mask is
/// symmetric left to right but not top to bottom, so this tells the four
/// quarter turns apart even when the ring gates are damaged.
fn mask_score(image: &Luma, h: &Homography, reference: &Reference) -> f64 {
    let level = |x: f64, y: f64| {
        let (lit, dark) = reference.at(x, y);
        (dot_samples(image, h, x, y, 8.0) - dark) / (lit - dark)
    };
    let tiles = (0..TILE_COUNT)
        .map(|tile| {
            let (x, y) = tile_center(tile);
            level(f64::from(x), f64::from(y))
        })
        .sum::<f64>()
        / TILE_COUNT as f64;
    let cells = empty_cells();
    let empty = cells.iter().map(|&(x, y)| level(x, y)).sum::<f64>() / cells.len() as f64;
    tiles - empty
}

/// Canonical index of the corner at index `index` of a finder quad under one
/// orientation hypothesis.
fn canonical_corner(index: usize, rotation: u8, mirrored: bool) -> usize {
    let r = usize::from(rotation);
    if mirrored {
        (r + 4 - index) % 4
    } else {
        (index + 4 - r) % 4
    }
}

/// The brightness summed over all ring slots under the pose that maps the canonical
/// corners onto `corners` (in quad order). The slots form the same set of points
/// under every quarter turn and mirror of the canvas (80, 92 and 104 are multiples
/// of four), so the value does not depend on the orientation.
fn ring_brightness(image: &Luma, corners: &[(f64, f64)]) -> Option<f64> {
    static SLOTS: OnceLock<Vec<(f64, f64)>> = OnceLock::new();
    let slots = SLOTS.get_or_init(|| {
        (0..TOTAL_SLOTS)
            .map(|flat| {
                let (ring, slot) = split_slot(flat);
                let (x, y) = slot_center(ring, slot);
                (f64::from(x), f64::from(y))
            })
            .collect()
    });
    let canonical: Vec<(f64, f64)> = FINDER_CENTERS
        .iter()
        .map(|&(x, y)| (f64::from(x), f64::from(y)))
        .collect();
    let h = Homography::from_points(&canonical, corners)?;
    Some(
        slots
            .iter()
            .map(|&(x, y)| dot_samples(image, &h, x, y, 3.5))
            .sum(),
    )
}

/// Moves an inferred corner to where the three dotted rings line up best: a 13 × 13
/// search in steps of 2 % of the mean leg around the parallelogram estimate, then a
/// 9 × 9 search in steps of 0.5 % around the best point. The rings fix the geometry
/// only; the orientation is decided afterwards by the gates and the `天`.
fn refine_inferred_corner(image: &Luma, corners: &[Finder; 4], inferred: usize) -> [Finder; 4] {
    let mut points: Vec<(f64, f64)> = corners.iter().map(|f| (f.x, f.y)).collect();
    let start = points[inferred];
    let distance =
        |o: usize| ((points[o].0 - start.0).powi(2) + (points[o].1 - start.1).powi(2)).sqrt();
    let leg = 0.5 * (distance((inferred + 1) % 4) + distance((inferred + 3) % 4));
    let mut best = (f64::MIN, start);
    let mut search = |centre: (f64, f64), step: f64, reach: i32, best: &mut (f64, (f64, f64))| {
        for dy in -reach..=reach {
            for dx in -reach..=reach {
                let candidate = (
                    centre.0 + f64::from(dx) * step,
                    centre.1 + f64::from(dy) * step,
                );
                points[inferred] = candidate;
                if let Some(brightness) = ring_brightness(image, &points)
                    && brightness > best.0
                {
                    *best = (brightness, candidate);
                }
            }
        }
    };
    search(start, 0.02 * leg, 6, &mut best);
    let coarse = best.1;
    search(coarse, 0.005 * leg, 4, &mut best);
    let mut refined = *corners;
    refined[inferred] = Finder {
        x: best.1.0,
        y: best.1.1,
        size: corners[inferred].size,
    };
    refined
}

fn gate_and_guard_slots() -> &'static (Vec<usize>, Vec<usize>) {
    static SLOTS: OnceLock<(Vec<usize>, Vec<usize>)> = OnceLock::new();
    SLOTS.get_or_init(|| {
        let roles = slot_roles();
        let gates = (0..roles.len())
            .filter(|&i| roles[i] == SlotRole::Gate)
            .collect();
        let guards = (0..roles.len())
            .filter(|&i| roles[i] == SlotRole::Guard)
            .collect();
        (gates, guards)
    })
}

fn normalised_dot(image: &Luma, h: &Homography, reference: &Reference, flat: usize) -> f64 {
    let (ring, slot) = split_slot(flat);
    let (x, y) = slot_center(ring, slot);
    let (x, y) = (f64::from(x), f64::from(y));
    let (lit, dark) = reference.at(x, y);
    (dot_samples(image, h, x, y, 3.5) - dark) / (lit - dark)
}

fn gate_score(image: &Luma, h: &Homography, reference: &Reference) -> f64 {
    let (gates, guards) = gate_and_guard_slots();
    let mean = |slots: &[usize]| {
        slots
            .iter()
            .map(|&s| normalised_dot(image, h, reference, s))
            .sum::<f64>()
            / slots.len() as f64
    };
    mean(gates) - mean(guards)
}

/// Reads lane `D`: returns the transmitted bytes and per-byte confidence.
fn read_dots(image: &Luma, h: &Homography, reference: &Reference) -> (Vec<u8>, Vec<f64>) {
    let (gates, guards) = gate_and_guard_slots();
    // per-ring thresholds from the gates (lit) and guards (dark)
    let mut thresholds = [0.5f64; RING_COUNT];
    for (ring, threshold) in thresholds.iter_mut().enumerate() {
        let in_ring = |flat: &&usize| split_slot(**flat).0 == ring;
        let lit: Vec<f64> = gates
            .iter()
            .filter(in_ring)
            .map(|&s| normalised_dot(image, h, reference, s))
            .collect();
        let dark: Vec<f64> = guards
            .iter()
            .filter(in_ring)
            .map(|&s| normalised_dot(image, h, reference, s))
            .collect();
        if !lit.is_empty() && !dark.is_empty() {
            let (l, d) = (
                lit.iter().sum::<f64>() / lit.len() as f64,
                dark.iter().sum::<f64>() / dark.len() as f64,
            );
            if l - d > 0.2 {
                *threshold = 0.5 * (l + d);
            }
        }
    }
    let mut bytes = vec![0u8; D_WORD];
    let mut confidence = vec![f64::MAX; D_WORD];
    for (bit, slot) in data_slots().into_iter().enumerate() {
        let value = normalised_dot(image, h, reference, slot);
        let threshold = thresholds[split_slot(slot).0];
        if value > threshold {
            bytes[bit / 8] |= 1 << (7 - bit % 8);
        }
        let c = &mut confidence[bit / 8];
        *c = c.min((value - threshold).abs());
    }
    debug_assert_eq!(D_BITS / 8, D_WORD);
    (bytes, confidence)
}

/// Lane `D` under one pose.
fn read_lane_d(image: &Luma, h: &Homography, reference: &Reference) -> Option<LaneResult> {
    let (word, confidence) = read_dots(image, h, reference);
    decode_with_erasures(Lane::D, &word, &confidence)
}

/// Tries Reed–Solomon with growing numbers of erasures, least confident first.
///
/// The schedule erases 0, ⅛, ¼, ⅓ and ½ of the parity bytes, and for lane `K` also ⅔. Lanes `D` and
/// `P` stop at ½: their words have only 11 and 13 parity bytes, and a further erasure step leaves
/// so few spare ones that it accepts wrong codewords (lane `D` at 7 erasures: about 0.4 % of random
/// words, and 5 wrong lanes in 2 900 simulated harsh frames; lane `P` at 8: 2 wrong lanes in 600
/// banded 480p frames). Capping them costs 0.65 % of the lane `D` reads and 0.15 % of the lane `P`
/// reads in those frames.
fn decode_with_erasures(lane: Lane, word: &[u8], confidence: &[f64]) -> Option<LaneResult> {
    let nsym = lane.parity_len();
    let mut order: Vec<usize> = (0..word.len()).collect();
    order.sort_by(|&a, &b| confidence[a].total_cmp(&confidence[b]));
    let mut schedule = vec![0, nsym / 8, nsym / 4, nsym / 3, nsym / 2];
    if lane == Lane::K {
        schedule.push(nsym * 2 / 3);
    }
    schedule.dedup();
    for erasures in schedule {
        let positions: Vec<usize> = order.iter().copied().take(erasures).collect();
        let mut trial = word.to_vec();
        // zero the erased bytes so stale values cannot leak through
        for &p in &positions {
            trial[p] = 0;
        }
        if let Ok((data, corrected)) = decode_lane_counted(lane, &trial, &positions) {
            return Some(LaneResult {
                data,
                corrected,
                erasures: positions.len(),
            });
        }
    }
    None
}

struct Patterns {
    /// `pred[b * 16 + g]`: expected normalised patch for polarity `b`, glyph `g`.
    pred: Vec<[f64; CELLS]>,
}

fn build_patterns(sigma: f64) -> Patterns {
    let kernel: Vec<f64> = {
        let radius = 2isize;
        let raw: Vec<f64> = (-radius..=radius)
            .map(|i| {
                if sigma < 0.05 {
                    f64::from(u8::from(i == 0))
                } else {
                    (-(i as f64).powi(2) / (2.0 * sigma * sigma)).exp()
                }
            })
            .collect();
        let sum: f64 = raw.iter().sum();
        raw.iter().map(|v| v / sum).collect()
    };
    let mut pred = Vec::with_capacity(2 * GLYPH_COUNT);
    for polarity in 0..2 {
        for template in &TEMPLATES {
            let coverage: Vec<f64> = template.iter().map(|&c| f64::from(c) / 255.0).collect();
            let mut blurred = [0.0; CELLS];
            for v in 0..PATCH {
                for u in 0..PATCH {
                    let mut acc = 0.0;
                    for (ky, wy) in kernel.iter().enumerate() {
                        for (kx, wx) in kernel.iter().enumerate() {
                            let (sx, sy) =
                                (u as isize + kx as isize - 2, v as isize + ky as isize - 2);
                            if (0..PATCH as isize).contains(&sx)
                                && (0..PATCH as isize).contains(&sy)
                            {
                                acc += wx * wy * coverage[sy as usize * PATCH + sx as usize];
                            }
                        }
                    }
                    blurred[v * PATCH + u] = acc;
                }
            }
            let mut pattern = [0.0; CELLS];
            for (p, &ink) in pattern.iter_mut().zip(&blurred) {
                *p = if polarity == 1 {
                    1.0 - (1.0 - INK_ON_LIGHT) * ink
                } else {
                    PINK_ON_DARK * ink
                };
            }
            pred.push(pattern);
        }
    }
    Patterns { pred }
}

struct TileRead {
    light: bool,
    glyph: u8,
    polarity_margin: f64,
    glyph_margin: f64,
    error: f64,
}

/// The raw 8×8 luma patch of every tile, as captured (no reference levels applied).
fn sample_patches(image: &Luma, h: &Homography) -> Vec<[f64; CELLS]> {
    let mut patches = vec![[0.0f64; CELLS]; TILE_COUNT];
    let half = f64::from(GLYPH_BOX) / 2.0;
    let cell = f64::from(GLYPH_BOX) / PATCH as f64;
    for (tile, patch) in patches.iter_mut().enumerate() {
        let (cx, cy) = tile_center(tile);
        let (cx, cy) = (f64::from(cx), f64::from(cy));
        for v in 0..PATCH {
            for u in 0..PATCH {
                let (gx, gy) = (
                    cx - half + (u as f64 + 0.5) * cell,
                    cy - half + (v as f64 + 0.5) * cell,
                );
                let mut sum = 0.0;
                for (ox, oy) in [(-0.25, -0.25), (0.25, -0.25), (-0.25, 0.25), (0.25, 0.25)] {
                    let (px, py) = h.apply(gx + ox * cell, gy + oy * cell);
                    sum += image.sample(px, py);
                }
                patch[v * PATCH + u] = sum / 4.0;
            }
        }
    }
    patches
}

/// The robust darkest and brightest level of a patch: the values `PATCH_CUT` cells in from
/// either end of the sorted cells.
fn patch_levels(values: &[f64; CELLS]) -> (f64, f64) {
    let mut sorted = *values;
    sorted.sort_by(f64::total_cmp);
    (sorted[PATCH_CUT], sorted[CELLS - 1 - PATCH_CUT])
}

/// Maps a patch's own darkest level to 0 and brightest to 1, with `floor` as the smallest
/// span that counts as contrast.
fn rescale(values: &[f64; CELLS], floor: f64) -> [f64; CELLS] {
    let (low, high) = patch_levels(values);
    let range = (high - low).max(floor);
    let mut out = [0.0; CELLS];
    for (o, &v) in out.iter_mut().zip(values) {
        *o = ((v - low) / range).clamp(-0.25, 1.25);
    }
    out
}

/// Picks for every patch the polarity and glyph whose template matches best.
///
/// The template blur is chosen per frame, by the lowest total error. With `rescale_templates`
/// the templates are rescaled like the patches; tiles flagged in `erased` get zero margins, so
/// they are the first the Reed–Solomon decoder treats as erasures.
fn classify(
    patches: &[[f64; CELLS]],
    sigmas: &[f64; 5],
    rescale_templates: bool,
    erased: &[bool],
) -> Vec<TileRead> {
    let mut best_total = f64::MAX;
    let mut best_reads = Vec::new();
    for &sigma in sigmas {
        let mut patterns = build_patterns(sigma);
        if rescale_templates {
            for pattern in &mut patterns.pred {
                *pattern = rescale(pattern, 0.001);
            }
        }
        let mut total = 0.0;
        let mut reads = Vec::with_capacity(TILE_COUNT);
        for (tile, patch) in patches.iter().enumerate() {
            let mut errors = [0.0f64; 2 * GLYPH_COUNT];
            for (hypothesis, error) in errors.iter_mut().enumerate() {
                *error = patch
                    .iter()
                    .zip(&patterns.pred[hypothesis])
                    .map(|(a, b)| (a - b) * (a - b))
                    .sum();
            }
            let best = (0..2 * GLYPH_COUNT)
                .min_by(|&a, &b| errors[a].total_cmp(&errors[b]))
                .unwrap_or(0);
            let polarity = best / GLYPH_COUNT;
            let glyph = best % GLYPH_COUNT;
            let other_polarity = (0..GLYPH_COUNT)
                .map(|g| errors[(1 - polarity) * GLYPH_COUNT + g])
                .fold(f64::MAX, f64::min);
            let other_glyph = (0..GLYPH_COUNT)
                .filter(|&g| g != glyph)
                .map(|g| errors[polarity * GLYPH_COUNT + g])
                .fold(f64::MAX, f64::min);
            total += errors[best];
            let (polarity_margin, glyph_margin) = if erased[tile] {
                (0.0, 0.0)
            } else {
                (other_polarity - errors[best], other_glyph - errors[best])
            };
            reads.push(TileRead {
                light: polarity == 1,
                glyph: glyph as u8,
                polarity_margin,
                glyph_margin,
                error: errors[best],
            });
        }
        if total < best_total {
            best_total = total;
            best_reads = reads;
        }
    }
    best_reads
}

/// Every patch normalised as `(v − dark) / (lit − dark)` with the light and dark levels measured
/// at the finders, interpolated to the tile.
fn levelled_patches(patches: &[[f64; CELLS]], reference: &Reference) -> Vec<[f64; CELLS]> {
    patches
        .iter()
        .enumerate()
        .map(|(tile, raw)| {
            let (cx, cy) = tile_center(tile);
            let (lit, dark) = reference.at(f64::from(cx), f64::from(cy));
            let mut patch = [0.0; CELLS];
            for (out, &value) in patch.iter_mut().zip(raw) {
                *out = (value - dark) / (lit - dark);
            }
            patch
        })
        .collect()
}

/// The level read: every patch is judged against the light and dark levels measured at the
/// finders, interpolated to the tile.
fn read_tiles(patches: &[[f64; CELLS]], reference: &Reference, sigmas: &[f64; 5]) -> Vec<TileRead> {
    classify(
        &levelled_patches(patches, reference),
        sigmas,
        false,
        &[false; TILE_COUNT],
    )
}

/// The normalised read: every patch and every template is rescaled by its own contrast
/// before they are compared, so the judgement does not depend on absolute levels.
fn read_tiles_normalised(patches: &[[f64; CELLS]], sigmas: &[f64; 5]) -> Vec<TileRead> {
    let spans: Vec<f64> = patches
        .iter()
        .map(|raw| {
            let (low, high) = patch_levels(raw);
            high - low
        })
        .collect();
    let median = {
        let mut sorted = spans.clone();
        sorted.sort_by(f64::total_cmp);
        sorted[TILE_COUNT / 2]
    };
    let mut erased = [false; TILE_COUNT];
    for (flag, &span) in erased.iter_mut().zip(&spans) {
        *flag = span < WEAK_TILE * median;
    }
    let scaled: Vec<[f64; CELLS]> = patches.iter().map(|raw| rescale(raw, 1.0)).collect();
    classify(&scaled, sigmas, true, &erased)
}

/// Lanes `P` and `K` from one set of patches: the level read first, then, for any lane still
/// unreadable, the normalised read.
fn read_tile_lanes(
    patches: &[[f64; CELLS]],
    reference: &Reference,
    sigmas: &[f64; 5],
) -> (Option<LaneResult>, Option<LaneResult>) {
    let reads = read_tiles(patches, reference, sigmas);
    let ((p_word, p_conf), (k_word, k_conf)) = tile_words(&reads);
    let mut p = decode_with_erasures(Lane::P, &p_word, &p_conf);
    let mut k = decode_with_erasures(Lane::K, &k_word, &k_conf);
    if p.is_none() || k.is_none() {
        let reads = read_tiles_normalised(patches, sigmas);
        let ((p_word, p_conf), (k_word, k_conf)) = tile_words(&reads);
        if p.is_none() {
            p = decode_with_erasures(Lane::P, &p_word, &p_conf);
        }
        if k.is_none() {
            k = decode_with_erasures(Lane::K, &k_word, &k_conf);
        }
    }
    (p, k)
}

/// A transmitted lane word with per-byte confidence.
type WordConfidence = (Vec<u8>, Vec<f64>);

fn tile_words(reads: &[TileRead]) -> (WordConfidence, WordConfidence) {
    let mut p = vec![0u8; P_WORD];
    let mut p_conf = vec![f64::MAX; P_WORD];
    let mut k = vec![0u8; K_WORD];
    let mut k_conf = vec![f64::MAX; K_WORD];
    for (tile, read) in reads.iter().enumerate() {
        if read.light {
            p[tile / 8] |= 1 << (7 - tile % 8);
        }
        let c = &mut p_conf[tile / 8];
        *c = c.min(read.polarity_margin);
        k[tile / 2] |= if tile % 2 == 0 {
            read.glyph << 4
        } else {
            read.glyph
        };
        let c = &mut k_conf[tile / 2];
        *c = c.min(read.glyph_margin.min(read.polarity_margin));
    }
    ((p, p_conf), (k, k_conf))
}

fn hypotheses(finders: &[Finder; 4], try_mirrored: bool) -> Vec<(u8, bool, Homography)> {
    let canonical: Vec<(f64, f64)> = FINDER_CENTERS
        .iter()
        .map(|&(x, y)| (f64::from(x), f64::from(y)))
        .collect();
    let mut out = Vec::new();
    for mirrored in [false, true] {
        if mirrored && !try_mirrored {
            continue;
        }
        for rotation in 0..4usize {
            let dst: Vec<(f64, f64)> = (0..4)
                .map(|i| {
                    let q = if mirrored {
                        finders[(rotation + 4 - i) % 4]
                    } else {
                        finders[(i + rotation) % 4]
                    };
                    (q.x, q.y)
                })
                .collect();
            if let Some(h) = Homography::from_points(&canonical, &dst) {
                out.push((rotation as u8, mirrored, h));
            }
        }
    }
    out
}

/// Whether `image` is something the decoder may work on: at least 48 pixels on a side, within
/// [`DecodeOptions::max_pixels`], and with a buffer that matches its size.
fn is_decodable(image: &Luma, options: &DecodeOptions) -> bool {
    image.width >= 48
        && image.height >= 48
        && image.width.saturating_mul(image.height) <= options.max_pixels
        && image.data.len() == image.width * image.height
}

/// Decodes one camera frame.
///
/// Tries the finder candidates of [`candidates`] in order and returns the first
/// that reads. For each, the
/// orientation hypotheses (four quarter turns, optionally mirrored) are ranked by
/// the ring gates plus the `天`; lane `D` is tried under the best three whose gate
/// score is at least 0.2, then the tile lanes under the best four.
///
/// # Errors
/// [`DecodeError::NoFinders`] when no code is visible and
/// [`DecodeError::NoOrientation`] when no orientation yields a readable lane.
pub fn decode(image: &Luma, options: &DecodeOptions) -> Result<DecodedFrame, DecodeError> {
    if !is_decodable(image, options) {
        return Err(DecodeError::UnsupportedImage);
    }
    let mut located = false;
    for set in candidates(image) {
        located = true;
        if let Some(frame) = decode_candidate(image, options, &set) {
            return Ok(frame);
        }
    }
    Err(if located {
        DecodeError::NoOrientation
    } else {
        DecodeError::NoFinders
    })
}

/// One hypothesis: gate score, `天` score, orientation, pose and levels.
type Scored = (f64, f64, u8, bool, Homography, Reference);

fn decode_candidate(
    image: &Luma,
    options: &DecodeOptions,
    set: &FinderSet,
) -> Option<DecodedFrame> {
    let corners = set.inferred.map_or(set.corners, |index| {
        refine_inferred_corner(image, &set.corners, index)
    });
    let mut scored: Vec<Scored> = hypotheses(&corners, options.try_mirrored)
        .into_iter()
        .filter_map(|(rotation, mirrored, h)| {
            let inferred = set
                .inferred
                .map(|index| canonical_corner(index, rotation, mirrored));
            let reference = reference_levels(image, &h, inferred)?;
            let gate = gate_score(image, &h, &reference);
            let mask = mask_score(image, &h, &reference);
            Some((gate, mask, rotation, mirrored, h, reference))
        })
        .collect();
    scored.sort_by(|a, b| (b.0 + b.1).total_cmp(&(a.0 + a.1)));
    let inferred_corner = |rotation: u8, mirrored: bool| {
        set.inferred
            .map(|index| canonical_corner(index, rotation, mirrored) as u8)
    };
    // 1. the ring beacon is the cheapest and strongest orientation check
    for (gate, _, rotation, mirrored, h, reference) in scored.iter().take(3) {
        if *gate < 0.2 {
            continue;
        }
        if let Some(d) = read_lane_d(image, h, reference) {
            let mut frame = finish(image, options, *rotation, *mirrored, *h, reference, Some(d));
            frame.inferred_corner = inferred_corner(*rotation, *mirrored);
            return Some(frame);
        }
    }
    // 2. fall back to the tile lanes under the most promising orientations
    for (_, _, rotation, mirrored, h, reference) in scored.iter().take(4) {
        let patches = sample_patches(image, h);
        let (p, k) = read_tile_lanes(&patches, reference, &options.template_sigmas);
        if p.is_some() || k.is_some() {
            return Some(DecodedFrame {
                homography: *h,
                rotation: *rotation,
                mirrored: *mirrored,
                p,
                k,
                d: read_lane_d(image, h, reference),
                inferred_corner: inferred_corner(*rotation, *mirrored),
            });
        }
    }
    None
}

fn finish(
    image: &Luma,
    options: &DecodeOptions,
    rotation: u8,
    mirrored: bool,
    h: Homography,
    reference: &Reference,
    d: Option<LaneResult>,
) -> DecodedFrame {
    let d = d.or_else(|| read_lane_d(image, &h, reference));
    let patches = sample_patches(image, &h);
    let (p, k) = read_tile_lanes(&patches, reference, &options.template_sigmas);
    DecodedFrame {
        homography: h,
        rotation,
        mirrored,
        p,
        k,
        d,
        inferred_corner: None,
    }
}

/// Follows a code from the previous frame that decoded, without searching the
/// whole image for finders (the most expensive part of [`decode`]).
///
/// Each corner finder seen in the previous frame is re-found near where the
/// previous pose puts it (see [`crate::locate::follow`]); the mean movement of those
/// predicts the rest. A corner inferred in the previous frame counts as seen again
/// only when its blossom is re-found within a quarter diameter of that prediction
/// (so a thumb beside it does not count). When exactly one corner is missing it
/// is placed at the prediction and refined against the rings like an inferred
/// corner. The orientation is kept from the previous frame. Returns `None` when
/// two corners are lost or no lane decodes; the caller then runs [`decode`].
#[must_use]
pub fn track(
    image: &Luma,
    previous: &DecodedFrame,
    options: &DecodeOptions,
) -> Option<DecodedFrame> {
    // a frame built by the caller may name a corner that does not exist
    if !is_decodable(image, options) || previous.inferred_corner.is_some_and(|c| c > 3) {
        return None;
    }
    let h0 = &previous.homography;
    let expected: Vec<Finder> = FINDER_CENTERS
        .iter()
        .map(|&(cx, cy)| {
            let (cx, cy) = (f64::from(cx), f64::from(cy));
            let (x, y) = h0.apply(cx, cy);
            let span =
                |a: (f64, f64), b: (f64, f64)| ((a.0 - b.0).powi(2) + (a.1 - b.1).powi(2)).sqrt();
            let size = span(h0.apply(cx - 60.0, cy), h0.apply(cx + 60.0, cy))
                .max(span(h0.apply(cx, cy - 60.0), h0.apply(cx, cy + 60.0)));
            Finder { x, y, size }
        })
        .collect();
    let short = image.width.min(image.height) as f64;
    if expected
        .iter()
        .any(|f| !(f.x.is_finite() && f.y.is_finite() && f.size.is_finite()) || f.size > short)
    {
        return None;
    }
    let previously_inferred = previous.inferred_corner.map(usize::from);
    let mut found: Vec<Option<Finder>> = expected
        .iter()
        .enumerate()
        .map(|(i, &e)| {
            if previously_inferred == Some(i) {
                None
            } else {
                follow(image, e)
            }
        })
        .collect();
    // the mean movement of the corners that were followed predicts the others
    let moved: Vec<(f64, f64)> = (0..4)
        .filter_map(|i| found[i].map(|f| (f.x - expected[i].x, f.y - expected[i].y)))
        .collect();
    if moved.len() < 3 {
        return None;
    }
    let shift = (
        moved.iter().map(|m| m.0).sum::<f64>() / moved.len() as f64,
        moved.iter().map(|m| m.1).sum::<f64>() / moved.len() as f64,
    );
    let predicted = |i: usize| Finder {
        x: expected[i].x + shift.0,
        y: expected[i].y + shift.1,
        size: expected[i].size,
    };
    // a corner that was hidden is seen again only when its blossom is found right where
    // the others say it is (a bright thumb beside it must not count)
    if let Some(m) = previously_inferred {
        let at = predicted(m);
        found[m] = follow(image, at)
            .filter(|f| ((f.x - at.x).powi(2) + (f.y - at.y).powi(2)).sqrt() <= 0.25 * at.size);
    }
    let lost: Vec<usize> = (0..4).filter(|&i| found[i].is_none()).collect();
    let inferred = match lost.as_slice() {
        [] => None,
        [m] => {
            found[*m] = Some(predicted(*m));
            Some(*m)
        }
        _ => return None,
    };
    let mut corners = [expected[0]; 4];
    for (corner, f) in corners.iter_mut().zip(&found) {
        *corner = (*f)?;
    }
    if let Some(m) = inferred {
        corners = refine_inferred_corner(image, &corners, m);
    }
    let canonical: Vec<(f64, f64)> = FINDER_CENTERS
        .iter()
        .map(|&(x, y)| (f64::from(x), f64::from(y)))
        .collect();
    let points: Vec<(f64, f64)> = corners.iter().map(|f| (f.x, f.y)).collect();
    let h = Homography::from_points(&canonical, &points)?;
    let reference = reference_levels(image, &h, inferred)?;
    let d = read_lane_d(image, &h, &reference);
    let patches = sample_patches(image, &h);
    let (p, k) = read_tile_lanes(&patches, &reference, &options.template_sigmas);
    if p.is_none() && k.is_none() && d.is_none() {
        return None;
    }
    Some(DecodedFrame {
        homography: h,
        rotation: previous.rotation,
        mirrored: previous.mirrored,
        p,
        k,
        d,
        inferred_corner: inferred.map(|m| m as u8),
    })
}

/// Reads all lanes with a known canvas-to-pixel homography (no finder search).
///
/// Returns `None` when the image is unusable (see [`DecodeError::UnsupportedImage`])
/// or the finder reference levels are too weak.
///
/// Used by trackers that already know the pose, by refinement passes and by
/// qualification tooling with a ground-truth pose. The reference levels come from
/// all four corner finders, so a frame whose corner blossom is hidden is refused
/// here (the hidden corner has no contrast); [`decode`] and [`track`] read such
/// frames by inferring that corner.
#[must_use]
pub fn decode_at(
    image: &Luma,
    homography: Homography,
    options: &DecodeOptions,
) -> Option<DecodedFrame> {
    if !is_decodable(image, options) {
        return None;
    }
    let reference = reference_levels(image, &homography, None)?;
    Some(finish(
        image, options, 0, false, homography, &reference, None,
    ))
}

/// Builds the cells a decoder believes it saw, for diagnostics.
///
/// Tiles are taken from the level read (the one that judges against the finder levels), even for
/// a frame whose lanes were rescued by the normalised read.
#[must_use]
pub fn observed_cells(
    image: &Luma,
    frame: &DecodedFrame,
    options: &DecodeOptions,
) -> Option<FrameCells> {
    if !is_decodable(image, options) {
        return None;
    }
    let inferred = frame.inferred_corner.map(usize::from);
    let reference = reference_levels(image, &frame.homography, inferred)?;
    let patches = sample_patches(image, &frame.homography);
    let reads = read_tiles(&patches, &reference, &options.template_sigmas);
    let ((p, _), (k, _)) = tile_words(&reads);
    let (d, _) = read_dots(image, &frame.homography, &reference);
    Some(FrameCells::from_words(&p, &k, &d))
}

/// Mean squared tile-match error of the level read, a quick image-quality indicator.
///
/// It can be large for a frame whose lanes were rescued by the normalised read, which is the
/// point: the finder levels did not describe that picture.
#[must_use]
pub fn tile_match_error(
    image: &Luma,
    frame: &DecodedFrame,
    options: &DecodeOptions,
) -> Option<f64> {
    if !is_decodable(image, options) {
        return None;
    }
    let inferred = frame.inferred_corner.map(usize::from);
    let reference = reference_levels(image, &frame.homography, inferred)?;
    let patches = sample_patches(image, &frame.homography);
    let reads = read_tiles(&patches, &reference, &options.template_sigmas);
    Some(reads.iter().map(|r| r.error).sum::<f64>() / reads.len() as f64)
}

/// What one capture shows of a frame's tile field: the 8×8 patch of every tile sampled under the
/// capture's decoded pose, in camera levels as [`decode`] samples them, and the finder levels of
/// that capture. Captures of one shown frame merge with [`merge_tiles`]. One evidence holds about
/// 128 KB.
#[derive(Debug, Clone, PartialEq)]
pub struct TileEvidence {
    patches: Vec<[f64; CELLS]>,
    reference: Reference,
}

/// The tile evidence of `image` under the pose `frame` was decoded with.
///
/// Returns `None` when the image is unusable (see [`DecodeError::UnsupportedImage`]), the frame
/// names a corner that does not exist, or the finder levels under that pose are too weak.
#[must_use]
pub fn tile_evidence(
    image: &Luma,
    frame: &DecodedFrame,
    options: &DecodeOptions,
) -> Option<TileEvidence> {
    // a frame built by the caller may name a corner that does not exist
    if !is_decodable(image, options) || frame.inferred_corner.is_some_and(|c| c > 3) {
        return None;
    }
    let inferred = frame.inferred_corner.map(usize::from);
    let reference = reference_levels(image, &frame.homography, inferred)?;
    Some(TileEvidence {
        patches: sample_patches(image, &frame.homography),
        reference,
    })
}

/// The cell-by-cell mean of several sets of patches, summed in the order given.
fn mean_patches<S: AsRef<[[f64; CELLS]]>>(sets: impl IntoIterator<Item = S>) -> Vec<[f64; CELLS]> {
    let mut mean = vec![[0.0f64; CELLS]; TILE_COUNT];
    let mut count = 0usize;
    for set in sets {
        count += 1;
        for (sum, patch) in mean.iter_mut().zip(set.as_ref()) {
            for (s, &value) in sum.iter_mut().zip(patch) {
                *s += value;
            }
        }
    }
    let count = count as f64;
    for patch in &mut mean {
        for value in patch.iter_mut() {
            *value /= count;
        }
    }
    mean
}

/// Lanes `P` and `K` from several captures of one shown frame.
///
/// The level read classifies the mean of every capture's patches levelled by its own finder
/// levels: for one template blur this picks the hypothesis with the least template error summed
/// over the captures, and it averages the sensor noise down. A lane it leaves unreadable is read
/// again from the normalised read of the mean raw patches. One evidence reads exactly the tile
/// lanes [`decode`] read from that capture. The caller checks that every evidence comes from
/// captures of the same shown frame: a lane read here names its frame in its own header.
#[must_use]
pub fn merge_tiles(
    evidence: &[TileEvidence],
    options: &DecodeOptions,
) -> (Option<LaneResult>, Option<LaneResult>) {
    if evidence.is_empty() {
        return (None, None);
    }
    let sigmas = &options.template_sigmas;
    let levelled = mean_patches(
        evidence
            .iter()
            .map(|e| levelled_patches(&e.patches, &e.reference)),
    );
    let reads = classify(&levelled, sigmas, false, &[false; TILE_COUNT]);
    let ((p_word, p_conf), (k_word, k_conf)) = tile_words(&reads);
    let mut p = decode_with_erasures(Lane::P, &p_word, &p_conf);
    let mut k = decode_with_erasures(Lane::K, &k_word, &k_conf);
    if p.is_none() || k.is_none() {
        let raw = mean_patches(evidence.iter().map(|e| &e.patches));
        let reads = read_tiles_normalised(&raw, sigmas);
        let ((p_word, p_conf), (k_word, k_conf)) = tile_words(&reads);
        if p.is_none() {
            p = decode_with_erasures(Lane::P, &p_word, &p_conf);
        }
        if k.is_none() {
            k = decode_with_erasures(Lane::K, &k_word, &k_conf);
        }
    }
    (p, k)
}

const _: () = {
    // keep the dot radius referenced so layout changes force a review here
    assert!(DOT_RADIUS > 3.5);
    let _ = ring_offset;
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::locate::locate;
    use crate::render::{RenderOptions, render};
    use crate::stream::StreamEncoder;

    fn setup(frame_no: u16) -> (StreamEncoder, crate::image::Rgb) {
        let payload: Vec<u8> = (0..300u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 11) as u8)
            .collect();
        let encoder = StreamEncoder::new(&payload, 2).unwrap();
        let rgb = render(
            &encoder.cells(frame_no),
            &RenderOptions {
                size: 768,
                supersample: 2,
                ..RenderOptions::default()
            },
        );
        (encoder, rgb)
    }

    #[test]
    fn clean_render_decodes_every_lane() {
        let (encoder, rgb) = setup(5);
        let decoded = decode(&rgb.to_luma(), &DecodeOptions::default()).expect("decodes");
        let (p, k, d) = encoder.lane_data(5);
        assert_eq!(decoded.p.as_ref().map(|l| &l.data), Some(&p));
        assert_eq!(decoded.k.as_ref().map(|l| &l.data), Some(&k));
        assert_eq!(decoded.d.as_ref().map(|l| &l.data), Some(&d));
        assert_eq!((decoded.rotation, decoded.mirrored), (0, false));
    }

    #[test]
    fn rotated_and_mirrored_renders_decode_with_the_right_orientation() {
        let (encoder, rgb) = setup(7);
        let (p, _, d) = encoder.lane_data(7);
        let n = rgb.width;
        let transform = |f: &dyn Fn(usize, usize) -> (usize, usize)| {
            let mut out = rgb.clone();
            for y in 0..n {
                for x in 0..n {
                    let (sx, sy) = f(x, y);
                    out.data[(y * n + x) * 3..(y * n + x) * 3 + 3]
                        .copy_from_slice(&rgb.data[(sy * n + sx) * 3..(sy * n + sx) * 3 + 3]);
                }
            }
            out.to_luma()
        };
        let cases: [(&str, Luma, u8, bool); 4] = [
            ("rot90", transform(&|x, y| (y, n - 1 - x)), 1, false),
            (
                "rot180",
                transform(&|x, y| (n - 1 - x, n - 1 - y)),
                2,
                false,
            ),
            ("rot270", transform(&|x, y| (n - 1 - y, x)), 3, false),
            // mirrored hypotheses enumerate corners in the opposite direction, so the
            // unrotated mirror reports quarter-turn index 1
            ("mirror", transform(&|x, y| (n - 1 - x, y)), 1, true),
        ];
        for (name, image, rotation, mirrored) in cases {
            let decoded =
                decode(&image, &DecodeOptions::default()).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(decoded.mirrored, mirrored, "{name}");
            assert_eq!(decoded.rotation, rotation, "{name} rotation");
            assert_eq!(
                decoded.d.as_ref().map(|l| &l.data),
                Some(&d),
                "{name} lane D"
            );
            assert_eq!(
                decoded.p.as_ref().map(|l| &l.data),
                Some(&p),
                "{name} lane P"
            );
        }
    }

    #[test]
    fn corrected_counts_rewritten_bytes_not_just_erasures() {
        let data: Vec<u8> = (0..crate::lanes::P_DATA as u8).collect();
        let mut word = crate::lanes::encode_lane(Lane::P, &data);
        for position in [2, 11, 30] {
            word[position] ^= 0x5A;
        }
        let confidence = vec![1.0; word.len()];
        let result = decode_with_erasures(Lane::P, &word, &confidence).expect("three errors fit");
        assert_eq!(result.data, data);
        assert_eq!(result.erasures, 0);
        assert_eq!(result.corrected, 3);
        // with the damaged bytes flagged as least confident, they become erasures
        let mut flagged = vec![1.0; word.len()];
        for position in [2, 11, 30] {
            flagged[position] = 0.0;
        }
        let result = decode_with_erasures(Lane::P, &word, &flagged).expect("decodes");
        assert_eq!(result.data, data);
        assert!(result.corrected >= 3);
    }

    /// The exact canvas-to-pixel homography of the 768-pixel test renders.
    fn render_homography() -> Homography {
        let canonical: Vec<(f64, f64)> = FINDER_CENTERS
            .iter()
            .map(|&(x, y)| (f64::from(x), f64::from(y)))
            .collect();
        let scale = 768.0 / 1024.0;
        let pixels: Vec<(f64, f64)> = canonical
            .iter()
            .map(|&(x, y)| (x * scale, y * scale))
            .collect();
        Homography::from_points(&canonical, &pixels).expect("homography")
    }

    /// A clean 768-pixel render with the exact canvas-to-pixel homography and its raw patches.
    fn clean_patches(frame: u16) -> (StreamEncoder, Luma, Homography, Vec<[f64; CELLS]>) {
        let (encoder, rgb) = setup(frame);
        let luma = rgb.to_luma();
        let h = render_homography();
        let patches = sample_patches(&luma, &h);
        (encoder, luma, h, patches)
    }

    #[test]
    fn level_and_normalised_reads_agree_on_a_clean_render() {
        let (encoder, luma, h, patches) = clean_patches(5);
        let (p_data, k_data, _) = encoder.lane_data(5);
        let sigmas = DecodeOptions::default().template_sigmas;
        let reference = reference_levels(&luma, &h, None).expect("reference levels");
        for (name, reads) in [
            ("level", read_tiles(&patches, &reference, &sigmas)),
            ("normalised", read_tiles_normalised(&patches, &sigmas)),
        ] {
            let ((p_word, p_conf), (k_word, k_conf)) = tile_words(&reads);
            let p = decode_with_erasures(Lane::P, &p_word, &p_conf).expect("lane P");
            let k = decode_with_erasures(Lane::K, &k_word, &k_conf).expect("lane K");
            assert_eq!((p.data, p.corrected), (p_data.clone(), 0), "{name}");
            assert_eq!((k.data, k.corrected), (k_data.clone(), 0), "{name}");
        }
    }

    #[test]
    fn normalised_read_cancels_gain_and_offset_per_tile() {
        let (encoder, luma, h, patches) = clean_patches(5);
        let (p_data, k_data, _) = encoder.lane_data(5);
        let sigmas = DecodeOptions::default().template_sigmas;
        // every tile gets its own gain and offset, as under glare, shadows and saturation
        let distorted: Vec<[f64; CELLS]> = patches
            .iter()
            .enumerate()
            .map(|(tile, raw)| {
                let gain = 0.35 + 0.65 * ((tile * 37 % 101) as f64 / 100.0);
                let offset = 5.0 + (tile * 53 % 61) as f64;
                let mut patch = [0.0; CELLS];
                for (out, &value) in patch.iter_mut().zip(raw) {
                    *out = gain * value + offset;
                }
                patch
            })
            .collect();
        let reference = reference_levels(&luma, &h, None).expect("reference levels");
        let reads = read_tiles(&distorted, &reference, &sigmas);
        let ((p_word, p_conf), _) = tile_words(&reads);
        assert!(
            decode_with_erasures(Lane::P, &p_word, &p_conf).is_none(),
            "the level read must not survive this distortion, or the test proves nothing"
        );
        let reads = read_tiles_normalised(&distorted, &sigmas);
        let ((p_word, p_conf), (k_word, k_conf)) = tile_words(&reads);
        let p = decode_with_erasures(Lane::P, &p_word, &p_conf).expect("lane P");
        let k = decode_with_erasures(Lane::K, &k_word, &k_conf).expect("lane K");
        assert_eq!((p.data, k.data), (p_data, k_data));
    }

    #[test]
    fn normalised_read_erases_tiles_that_lost_their_contrast() {
        let (_, _, _, mut patches) = clean_patches(5);
        patches[5] = [100.0; CELLS];
        patches[9] = [30.0; CELLS];
        let reads = read_tiles_normalised(&patches, &DecodeOptions::default().template_sigmas);
        for tile in [5, 9] {
            assert!(reads[tile].polarity_margin.abs() < 1e-12, "tile {tile}");
            assert!(reads[tile].glyph_margin.abs() < 1e-12, "tile {tile}");
        }
        assert!(reads[6].polarity_margin > 0.0 && reads[6].glyph_margin > 0.0);
    }

    #[test]
    fn patch_levels_ignore_the_extreme_cells() {
        let mut values = [10.0; CELLS];
        for (i, value) in values.iter_mut().enumerate().take(CELLS / 2) {
            *value = 200.0 + (i % 3) as f64;
        }
        values[0] = 255.0; // one hot cell
        values[CELLS - 1] = 0.0; // one dead cell
        let (low, high) = patch_levels(&values);
        assert!((low - 10.0).abs() < 1e-12);
        assert!((200.0..=202.0).contains(&high));
        let scaled = rescale(&values, 1.0);
        assert!(scaled.iter().all(|v| (-0.25..=1.25).contains(v)));
        // a flat patch stays flat instead of dividing by nothing
        assert!(rescale(&[7.0; CELLS], 1.0).iter().all(|v| v.abs() < 1e-12));
    }

    #[test]
    fn shadowed_part_of_a_render_decodes_through_the_normalised_read() {
        let (encoder, rgb) = setup(5);
        let (p_data, k_data, _) = encoder.lane_data(5);
        let mut luma = rgb.to_luma();
        let width = luma.width;
        for row in luma.data.chunks_mut(width) {
            for value in &mut row[width * 7 / 20..width * 3 / 5] {
                *value = (f64::from(*value) * 0.3).round() as u8;
            }
        }
        // the finder levels cannot describe a step in the light: the level read loses lane K
        let h = render_homography();
        let sigmas = DecodeOptions::default().template_sigmas;
        let reference = reference_levels(&luma, &h, None).expect("reference levels");
        let reads = read_tiles(&sample_patches(&luma, &h), &reference, &sigmas);
        let (_, (k_word, k_conf)) = tile_words(&reads);
        assert!(decode_with_erasures(Lane::K, &k_word, &k_conf).is_none());
        let decoded = decode(&luma, &DecodeOptions::default()).expect("decodes");
        assert_eq!(decoded.p.as_ref().map(|l| &l.data), Some(&p_data));
        assert_eq!(decoded.k.as_ref().map(|l| &l.data), Some(&k_data));
    }

    #[test]
    fn random_words_are_almost_never_accepted() {
        // Reed–Solomon with erasures can accept a word that is not a transmission. Lane D has only
        // 11 parity bytes, so its schedule stops at five erasures; at seven it let through about
        // one random word in 250 (150 of these 40 000). Lane P stops at six for the same reason. The counts are exact so that every SDK port,
        // fed the same xorshift32 words and byte-valued confidences (many ties, so the ranking must
        // be stable), reproduces the decoder bit for bit.
        let mut rng = crate::prng::Xorshift32::new(0x5EED);
        let trials = 40_000;
        for (lane, expected) in [(Lane::D, 3), (Lane::P, 0)] {
            let len = lane.data_len() + lane.parity_len();
            let mut accepted = 0;
            for _ in 0..trials {
                let word: Vec<u8> = (0..len).map(|_| rng.next_byte()).collect();
                let confidence: Vec<f64> = (0..len).map(|_| f64::from(rng.next_byte())).collect();
                accepted += usize::from(decode_with_erasures(lane, &word, &confidence).is_some());
            }
            assert_eq!(accepted, expected, "lane {lane:?} of {trials} random words");
        }
    }

    #[test]
    fn only_lane_k_uses_two_thirds_of_its_parity_as_erasures() {
        // damaged bytes: `flagged` of them marked least confident, two more hidden. With the extra
        // erasure step of the old schedule the decoder would repair them (2·2 + flagged parity
        // bytes); the capped schedule must refuse instead of risking a wrong codeword.
        for (lane, flagged) in [(Lane::D, 7), (Lane::P, 8)] {
            let data: Vec<u8> = (0..lane.data_len() as u8).collect();
            let word = crate::lanes::encode_lane(lane, &data);
            let mut damaged = word.clone();
            let mut confidence = vec![1.0; word.len()];
            for position in 0..flagged {
                damaged[position] ^= 0xA5;
                confidence[position] = 0.0;
            }
            damaged[20] ^= 0x3C;
            damaged[21] ^= 0x3C;
            assert!(
                decode_with_erasures(lane, &damaged, &confidence).is_none(),
                "lane {lane:?}"
            );
            // half the parity flagged plus one hidden error stays comfortably repairable
            let mut damaged = word;
            let mut confidence = vec![1.0; damaged.len()];
            for position in 0..lane.parity_len() / 2 {
                damaged[position] ^= 0xA5;
                confidence[position] = 0.0;
            }
            damaged[20] ^= 0x3C;
            let result = decode_with_erasures(lane, &damaged, &confidence).expect("repairable");
            assert_eq!(result.data, data, "lane {lane:?}");
            assert!(result.erasures <= lane.parity_len() / 2, "lane {lane:?}");
        }
        // lane K keeps the two-thirds step: 30 flagged bytes plus 7 hidden errors need it
        // (2·7 + 30 = 44 of 45 parity bytes)
        let data: Vec<u8> = (0..crate::lanes::K_DATA).map(|i| i as u8).collect();
        let word = crate::lanes::encode_lane(Lane::K, &data);
        let mut damaged = word;
        let mut confidence = vec![1.0; damaged.len()];
        for position in 0..30 {
            damaged[position] ^= 0xA5;
            confidence[position] = 0.0;
        }
        for byte in &mut damaged[60..67] {
            *byte ^= 0x3C;
        }
        let result = decode_with_erasures(Lane::K, &damaged, &confidence).expect("30 erasures");
        assert_eq!((result.data, result.erasures), (data, 30));
    }

    #[test]
    fn equal_confidences_are_erased_in_position_order() {
        // Every tile the normalised read erases has confidence exactly 0, so ties are the rule, and
        // the ranking must be stable or ports disagree about which bytes are erased. Three damaged
        // bytes at the front plus four hidden ones fit lane D only if exactly the first three
        // positions are erased (3 erasures + 4 errors = all 11 parity bytes): a step that erased
        // the last positions instead would see seven errors.
        let data: Vec<u8> = (0..crate::lanes::D_DATA as u8).collect();
        let mut word = crate::lanes::encode_lane(Lane::D, &data);
        for position in (0..3).chain(20..24) {
            word[position] ^= 0x5A;
        }
        let confidence = vec![1.0; word.len()];
        let result = decode_with_erasures(Lane::D, &word, &confidence).expect("ties in order");
        assert_eq!(
            (result.data, result.erasures, result.corrected),
            (data, 3, 7)
        );
    }

    #[test]
    fn blank_frames_report_no_finders() {
        assert_eq!(
            decode(&Luma::new(320, 240), &DecodeOptions::default()),
            Err(DecodeError::NoFinders)
        );
    }

    #[test]
    fn unusable_sizes_are_rejected_without_work() {
        let options = DecodeOptions::default();
        assert_eq!(
            decode(&Luma::new(1, 1), &options),
            Err(DecodeError::UnsupportedImage)
        );
        assert_eq!(
            decode(&Luma::new(47, 400), &options),
            Err(DecodeError::UnsupportedImage)
        );
        assert_eq!(
            decode(&Luma::new(0, 0), &options),
            Err(DecodeError::UnsupportedImage)
        );
        let small_budget = DecodeOptions {
            max_pixels: 1_000,
            ..options
        };
        assert_eq!(
            decode(&Luma::new(100, 100), &small_budget),
            Err(DecodeError::UnsupportedImage)
        );
        let broken = Luma {
            width: 100,
            height: 100,
            data: vec![0; 5],
        };
        assert_eq!(
            decode(&broken, &options),
            Err(DecodeError::UnsupportedImage)
        );
        assert!(
            decode_at(
                &Luma::new(8, 8),
                crate::geometry::Homography::IDENTITY,
                &options
            )
            .is_none()
        );
        // a buffer that does not match the stated size must not reach the sampler
        assert!(decode_at(&broken, crate::geometry::Homography::IDENTITY, &options).is_none());
        let (_, rgb) = setup(5);
        let decoded = decode(&rgb.to_luma(), &options).expect("decodes");
        assert!(observed_cells(&broken, &decoded, &options).is_none());
        assert!(tile_match_error(&broken, &decoded, &options).is_none());
    }

    #[test]
    fn garbage_images_never_panic_or_decode() {
        let mut rng = crate::prng::Xorshift32::new(99);
        for (w, h) in [(64usize, 48usize), (257, 129), (320, 240), (480, 480)] {
            for style in 0..4 {
                let data: Vec<u8> = (0..w * h)
                    .map(|i| match style {
                        0 => rng.next_byte(),           // white noise
                        1 => ((i % w) * 255 / w) as u8, // gradient
                        2 => {
                            if (i / w / 8 + i % w / 8) % 2 == 0 {
                                230
                            } else {
                                20
                            }
                        } // checkerboard
                        _ => {
                            if rng.next_u32().is_multiple_of(50) {
                                255
                            } else {
                                0
                            }
                        } // sparse specks
                    })
                    .collect();
                let image = Luma {
                    width: w,
                    height: h,
                    data,
                };
                assert!(
                    decode(&image, &DecodeOptions::default()).is_err(),
                    "{w}x{h} style {style}"
                );
            }
        }
    }

    #[test]
    fn random_blob_scenes_never_panic() {
        // Scenes with several random bright ellipses (some finder-sized) on noise:
        // exercises the locator, quad selection and homography on degenerate layouts.
        let mut rng = crate::prng::Xorshift32::new(2024);
        for scene in 0..60 {
            let (w, h) = (
                160 + (rng.next_u32() % 400) as usize,
                120 + (rng.next_u32() % 300) as usize,
            );
            let mut data: Vec<u8> = (0..w * h).map(|_| (rng.next_u32() % 40) as u8).collect();
            let blobs = 3 + rng.next_u32() % 8;
            for _ in 0..blobs {
                let (cx, cy) = (
                    (rng.next_u32() as usize % w) as f64,
                    (rng.next_u32() as usize % h) as f64,
                );
                let (rx, ry) = (
                    6.0 + f64::from(rng.next_u32() % 40),
                    6.0 + f64::from(rng.next_u32() % 40),
                );
                for y in 0..h {
                    for x in 0..w {
                        let (dx, dy) = ((x as f64 - cx) / rx, (y as f64 - cy) / ry);
                        if dx * dx + dy * dy <= 1.0 {
                            data[y * w + x] = 230;
                        }
                    }
                }
            }
            let image = Luma {
                width: w,
                height: h,
                data,
            };
            // must not panic; a lucky layout may locate finders but cannot yield lanes
            if let Ok(frame) = decode(&image, &DecodeOptions::default()) {
                assert_eq!(
                    frame.lanes_ok(),
                    0,
                    "scene {scene} produced lane data from blobs"
                );
            }
        }
    }

    /// A 768-pixel render of frame `frame_no` with the blossom of canonical corner
    /// `corner` painted over with background.
    fn hidden_blossom(frame_no: u16, corner: usize) -> (StreamEncoder, crate::image::Rgb) {
        let (encoder, mut rgb) = setup(frame_no);
        let n = rgb.width;
        let scale = n as f64 / 1024.0;
        let (cx, cy) = FINDER_CENTERS[corner];
        let (cx, cy) = (f64::from(cx) * scale, f64::from(cy) * scale);
        for y in 0..n {
            for x in 0..n {
                let (dx, dy) = (x as f64 + 0.5 - cx, y as f64 + 0.5 - cy);
                if dx * dx + dy * dy <= (75.0 * scale).powi(2) {
                    rgb.data[(y * n + x) * 3..(y * n + x) * 3 + 3].fill(0);
                }
            }
        }
        (encoder, rgb)
    }

    #[test]
    fn a_hidden_blossom_is_inferred_and_every_lane_still_reads() {
        for corner in 0..4 {
            let (encoder, rgb) = hidden_blossom(2, corner);
            let luma = rgb.to_luma();
            let decoded = decode(&luma, &DecodeOptions::default()).expect("decodes");
            let (p, k, d) = encoder.lane_data(2);
            assert_eq!(
                decoded.inferred_corner,
                Some(corner as u8),
                "corner {corner}"
            );
            assert_eq!(
                (decoded.rotation, decoded.mirrored),
                (0, false),
                "corner {corner}"
            );
            assert_eq!(decoded.p.map(|l| l.data), Some(p), "corner {corner} lane P");
            assert_eq!(decoded.k.map(|l| l.data), Some(k), "corner {corner} lane K");
            assert_eq!(decoded.d.map(|l| l.data), Some(d), "corner {corner} lane D");
        }
    }

    #[test]
    fn the_inferred_corner_is_reported_in_code_coordinates_when_mirrored() {
        // hide the top-right blossom of the code, then mirror the picture: the hidden
        // blossom appears top-left in the image but is still corner 1 of the code
        let (encoder, rgb) = hidden_blossom(3, 1);
        let n = rgb.width;
        let mut mirrored = rgb.clone();
        for y in 0..n {
            for x in 0..n {
                let (src, dst) = ((y * n + (n - 1 - x)) * 3, (y * n + x) * 3);
                mirrored.data[dst..dst + 3].copy_from_slice(&rgb.data[src..src + 3]);
            }
        }
        let decoded = decode(&mirrored.to_luma(), &DecodeOptions::default()).expect("decodes");
        assert!(decoded.mirrored);
        assert_eq!(decoded.inferred_corner, Some(1));
        assert_eq!(decoded.d.map(|l| l.data), Some(encoder.lane_data(3).2));
    }

    #[test]
    fn a_large_hidden_region_never_reads_wrong_data() {
        // the whole bottom-right quarter is gone: rings and tiles with it
        let (encoder, mut rgb) = setup(2);
        let n = rgb.width;
        for y in n * 3 / 4..n {
            for x in n * 3 / 4..n {
                rgb.data[(y * n + x) * 3..(y * n + x) * 3 + 3].fill(0);
            }
        }
        let (p, k, d) = encoder.lane_data(2);
        if let Ok(frame) = decode(&rgb.to_luma(), &DecodeOptions::default()) {
            for (lane, truth) in [(frame.p, p), (frame.k, k), (frame.d, d)] {
                if let Some(lane) = lane {
                    assert_eq!(lane.data, truth);
                }
            }
        }
    }

    /// Shifts a luma image by whole pixels, filling with black.
    fn shifted(image: &Luma, dx: isize, dy: isize) -> Luma {
        let mut out = Luma::new(image.width, image.height);
        for y in 0..image.height as isize {
            for x in 0..image.width as isize {
                let (sx, sy) = (x - dx, y - dy);
                if sx >= 0 && sy >= 0 && sx < image.width as isize && sy < image.height as isize {
                    out.data[y as usize * image.width + x as usize] =
                        image.data[sy as usize * image.width + sx as usize];
                }
            }
        }
        out
    }

    /// Places a luma image in the middle of a larger black frame.
    fn padded(image: &Luma, pad: usize) -> Luma {
        let width = image.width + 2 * pad;
        let mut out = Luma::new(width, image.height + 2 * pad);
        for (y, row) in image.data.chunks(image.width).enumerate() {
            let start = (y + pad) * width + pad;
            out.data[start..start + image.width].copy_from_slice(row);
        }
        out
    }

    #[test]
    fn tracking_follows_a_small_movement_and_gives_up_on_a_jump() {
        let (encoder, rgb) = setup(6);
        let luma = padded(&rgb.to_luma(), 100);
        let options = DecodeOptions::default();
        let first = decode(&luma, &options).expect("decodes");
        let (p, k, d) = encoder.lane_data(6);
        let moved = shifted(&luma, 9, -6);
        let followed = track(&moved, &first, &options).expect("tracks a 9 px move");
        assert_eq!(followed.p.map(|l| l.data), Some(p));
        assert_eq!(followed.k.map(|l| l.data), Some(k));
        assert_eq!(followed.d.map(|l| l.data), Some(d));
        assert_eq!(followed.inferred_corner, None);
        // more than a finder diameter: tracking refuses, a full decode is needed
        let jumped = shifted(&luma, 95, 0);
        assert!(track(&jumped, &first, &options).is_none());
        assert!(decode(&jumped, &options).is_ok());
    }

    #[test]
    fn broken_poses_are_refused_without_panicking() {
        let options = DecodeOptions::default();
        let (_, rgb) = setup(4);
        let luma = rgb.to_luma();
        let mut previous = decode(&luma, &options).expect("decodes");
        // a good pose that names a corner that does not exist
        assert!(track(&luma, &previous, &options).is_some());
        for corner in [4, 255] {
            previous.inferred_corner = Some(corner);
            assert!(track(&luma, &previous, &options).is_none());
        }
        let non_finite = [
            Homography([f64::NAN; 9]),
            Homography([f64::INFINITY, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0]),
        ];
        for broken in non_finite {
            assert!(decode_at(&luma, broken, &options).is_none());
        }
        // the last one makes every finder far larger than the image
        let huge = Homography([50.0, 0.0, 0.0, 0.0, 50.0, 0.0, 0.0, 0.0, 1.0]);
        for broken in non_finite.into_iter().chain([huge]) {
            for inferred in [None, Some(2)] {
                previous.homography = broken;
                previous.inferred_corner = inferred;
                assert!(track(&luma, &previous, &options).is_none());
            }
        }
    }

    #[test]
    fn tracking_survives_a_blossom_that_disappears() {
        let options = DecodeOptions::default();
        let (_, rgb) = setup(4);
        let first = decode(&rgb.to_luma(), &options).expect("decodes");
        // the same code, slightly moved, now with the bottom-left blossom covered
        let (encoder, covered) = hidden_blossom(4, 3);
        let moved = shifted(&covered.to_luma(), -5, 4);
        let followed = track(&moved, &first, &options).expect("tracks with three blossoms");
        assert_eq!(followed.inferred_corner, Some(3));
        assert_eq!(followed.d.map(|l| l.data), Some(encoder.lane_data(4).2));
    }

    #[test]
    fn a_blossom_that_reappears_is_seen_again() {
        let options = DecodeOptions::default();
        let (_, covered) = hidden_blossom(4, 3);
        let first = decode(&covered.to_luma(), &options).expect("decodes");
        assert_eq!(first.inferred_corner, Some(3));
        // the thumb moves away and the hand moves a little
        let (encoder, rgb) = setup(4);
        let moved = shifted(&rgb.to_luma(), 4, -3);
        let followed = track(&moved, &first, &options).expect("tracks");
        assert_eq!(followed.inferred_corner, None);
        assert_eq!(followed.d.map(|l| l.data), Some(encoder.lane_data(4).2));
        // still covered: still inferred
        let still = shifted(&covered.to_luma(), 4, -3);
        let followed = track(&still, &first, &options).expect("tracks");
        assert_eq!(followed.inferred_corner, Some(3));
    }

    /// A canvas-sized image with the given finder (lit) and reference-canvas (dark)
    /// levels painted where [`reference_levels`] samples them.
    fn level_card(levels: [(u8, u8); 4]) -> Luma {
        let mut luma = Luma::new(1024, 1024);
        let mut paint = |cx: f64, cy: f64, radius: f64, value: u8| {
            for y in (cy - radius) as usize..=(cy + radius) as usize {
                for x in (cx - radius) as usize..=(cx + radius) as usize {
                    luma.data[y * 1024 + x] = value;
                }
            }
        };
        for (&(cx, cy), &(lit, dark)) in FINDER_CENTERS.iter().zip(&levels) {
            let (cx, cy) = (f64::from(cx), f64::from(cy));
            let (sx, sy) = (
                if cx < 512.0 { 1.0 } else { -1.0 },
                if cy < 512.0 { 1.0 } else { -1.0 },
            );
            paint(cx, cy, 30.0, lit);
            paint(cx + sx * 100.0, cy, 12.0, dark);
            paint(cx, cy + sy * 100.0, 12.0, dark);
        }
        luma
    }

    #[test]
    fn an_inferred_corner_needs_contrast_too() {
        let h = Homography::IDENTITY;
        // even light: the hidden corner (3) gets levels between the others'
        let even = level_card([(230, 30), (220, 25), (210, 20), (0, 0)]);
        let reference = reference_levels(&even, &h, Some(3)).expect("levels");
        assert!(
            reference.lit[3] - reference.dark[3] >= 12.0,
            "{:?} {:?}",
            reference.lit,
            reference.dark
        );
        // the hidden corner's neighbours disagree (one dim, one veiled): the
        // estimates cross, so the corner cannot be read
        let uneven = level_card([(60, 45), (250, 20), (200, 185), (0, 0)]);
        assert!(reference_levels(&uneven, &h, Some(3)).is_none());
        // with every corner seen, the same light is fine
        let seen = level_card([(60, 45), (250, 20), (200, 185), (240, 20)]);
        assert!(reference_levels(&seen, &h, None).is_some());
    }

    #[test]
    fn the_tian_mask_tells_the_quarter_turns_apart() {
        let (_, rgb) = setup(5);
        let luma = rgb.to_luma();
        let quad = locate(&luma).expect("four finders");
        let mut by_rotation = [f64::MIN; 4];
        for (rotation, mirrored, h) in hypotheses(&quad, true) {
            let reference = reference_levels(&luma, &h, None).expect("levels");
            let score = mask_score(&luma, &h, &reference);
            if !mirrored {
                by_rotation[usize::from(rotation)] = score;
            }
        }
        // upright wins clearly over the three other quarter turns
        for rotation in 1..4 {
            assert!(
                by_rotation[0] > by_rotation[rotation] + 0.1,
                "{by_rotation:?}"
            );
        }
    }

    #[test]
    fn merging_one_capture_reads_the_tile_lanes_decode_read() {
        let options = DecodeOptions::default();
        let (_, clean) = setup(5);
        // a shadow band that only the normalised read gets through
        let mut shadowed = clean.to_luma();
        let width = shadowed.width;
        for row in shadowed.data.chunks_mut(width) {
            for value in &mut row[width * 7 / 20..width * 3 / 5] {
                *value = (f64::from(*value) * 0.3).round() as u8;
            }
        }
        let (_, hidden) = hidden_blossom(2, 3);
        let n = hidden.width;
        let mut mirrored = hidden.clone();
        for y in 0..n {
            for x in 0..n {
                let (src, dst) = ((y * n + (n - 1 - x)) * 3, (y * n + x) * 3);
                mirrored.data[dst..dst + 3].copy_from_slice(&hidden.data[src..src + 3]);
            }
        }
        for (name, image) in [
            ("clean", clean.to_luma()),
            ("shadowed", shadowed),
            ("hidden corner", hidden.to_luma()),
            ("mirrored hidden corner", mirrored.to_luma()),
        ] {
            let frame = decode(&image, &options).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(frame.p.is_some() && frame.k.is_some(), "{name}");
            let evidence = tile_evidence(&image, &frame, &options).expect("evidence");
            assert_eq!(
                merge_tiles(&[evidence], &options),
                (frame.p.clone(), frame.k.clone()),
                "{name}"
            );
        }
    }

    /// Uniform noise of ±382 levels per cell: far more than one capture's tile read survives.
    const NOISE_TEST_GAIN: f64 = 3.0;

    #[test]
    fn averaging_captures_cancels_their_independent_noise() {
        let (encoder, luma, h, patches) = clean_patches(5);
        let (p_data, k_data, _) = encoder.lane_data(5);
        let reference = reference_levels(&luma, &h, None).expect("reference levels");
        let options = DecodeOptions::default();
        let mut rng = crate::prng::Xorshift32::new(9);
        let captures: Vec<TileEvidence> = (0..4)
            .map(|_| TileEvidence {
                patches: patches
                    .iter()
                    .map(|raw| {
                        let mut patch = *raw;
                        for value in &mut patch {
                            *value += (f64::from(rng.next_byte()) - 127.5) * NOISE_TEST_GAIN;
                        }
                        patch
                    })
                    .collect(),
                reference,
            })
            .collect();
        for capture in &captures {
            assert!(
                merge_tiles(std::slice::from_ref(capture), &options)
                    .1
                    .is_none(),
                "one noisy capture must not read lane K, or the test proves nothing"
            );
        }
        let (p, k) = merge_tiles(&captures, &options);
        assert_eq!(p.map(|l| l.data), Some(p_data));
        assert_eq!(k.map(|l| l.data), Some(k_data));
    }

    #[test]
    fn evidence_needs_a_usable_image_and_a_real_corner() {
        let options = DecodeOptions::default();
        let (_, rgb) = setup(5);
        let image = rgb.to_luma();
        let mut frame = decode(&image, &options).expect("decodes");
        assert!(tile_evidence(&Luma::new(20, 20), &frame, &options).is_none());
        frame.inferred_corner = Some(7);
        assert!(tile_evidence(&image, &frame, &options).is_none());
        assert_eq!(merge_tiles(&[], &options), (None, None));
    }
}
