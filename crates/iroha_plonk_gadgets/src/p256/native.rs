//! Native P-256 reference arithmetic: Montgomery field arithmetic modulo
//! `p` and `n`, Jacobian group operations (`a = -3`), the ECDSA verdict of
//! the KAGEMUSHA profile (prehashed, low-S), the per-limb window layouts and
//! the fixed-base window tables of the chip.
//!
//! Field multiplication, addition and inversion are constant time in their
//! operands (masked final subtractions, fixed-length exponentiation). The
//! group operations, scalar multiplication, the verdict and the table
//! builders branch on their inputs: they serve public constants (window
//! tables, curve points) and test oracles, never secret witness values.

use core::cmp::Ordering;

pub use crate::ff::mont::MontModulus;
use crate::ff::{ForeignModulus, LIMB_BITS, LIMBS, Nat, TOP_LIMB_BITS};

/// The P-256 base field order `p` (little-endian words).
pub const P: [u64; 4] = ForeignModulus::P256_BASE.words();
/// The P-256 group order `n` (little-endian words).
pub const N: [u64; 4] = ForeignModulus::P256_ORDER.words();
/// The curve coefficient `b` of `y^2 = x^3 - 3 x + b`.
pub const B: [u64; 4] = [
    0x3bce_3c3e_27d2_604b,
    0x651d_06b0_cc53_b0f6,
    0xb3eb_bd55_7698_86bc,
    0x5ac6_35d8_aa3a_93e7,
];
/// The generator's `x`.
pub const GX: [u64; 4] = [
    0xf4a1_3945_d898_c296,
    0x7703_7d81_2deb_33a0,
    0xf8bc_e6e5_63a4_40f2,
    0x6b17_d1f2_e12c_4247,
];
/// The generator's `y`.
pub const GY: [u64; 4] = [
    0xcbb6_4068_37bf_51f5,
    0x2bce_3357_6b31_5ece,
    0x8ee7_eb4a_7c0f_9e16,
    0x4fe3_42e2_fe1a_7f9b,
];
/// The low-S bound `(n - 1) / 2`: a signature's `s` must not exceed it.
pub const HALF_N: [u64; 4] = [
    0x79dc_e561_7e31_92a8,
    0xde73_7d56_d38b_cf42,
    0x7fff_ffff_ffff_ffff,
    0x7fff_ffff_8000_0000,
];

/// `a < b` for little-endian words.
#[must_use]
pub fn words_lt(a: &[u64; 4], b: &[u64; 4]) -> bool {
    words_cmp(a, b) == Ordering::Less
}

/// Compares little-endian words (variable time).
#[must_use]
pub fn words_cmp(a: &[u64; 4], b: &[u64; 4]) -> Ordering {
    for index in (0..4).rev() {
        match a[index].cmp(&b[index]) {
            Ordering::Equal => {}
            other => return other,
        }
    }
    Ordering::Equal
}

/// Whether every word is zero.
#[must_use]
pub fn words_is_zero(a: &[u64; 4]) -> bool {
    a.iter().all(|word| *word == 0)
}

/// Montgomery constants of `p`.
pub const BASE: MontModulus = MontModulus::new(P);
/// Montgomery constants of `n`.
pub const ORDER: MontModulus = MontModulus::new(N);

/// An affine point with canonical coordinates (never the identity).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Affine {
    /// `x < p`.
    pub x: [u64; 4],
    /// `y < p`.
    pub y: [u64; 4],
}

impl Affine {
    /// The generator.
    pub const GENERATOR: Self = Self { x: GX, y: GY };

    /// Whether the coordinates are canonical and satisfy
    /// `y^2 = x^3 - 3 x + b`.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        words_lt(&self.x, &P) && words_lt(&self.y, &P) && on_curve(&self.x, &self.y)
    }

    /// `-P`.
    #[must_use]
    pub fn neg(&self) -> Self {
        Self {
            x: self.x,
            y: BASE.neg(&self.y),
        }
    }
}

/// Whether canonical `(x, y)` satisfies the curve equation.
#[must_use]
pub fn on_curve(x: &[u64; 4], y: &[u64; 4]) -> bool {
    let x2 = BASE.mul(x, x);
    let x3 = BASE.mul(&x2, x);
    let three_x = BASE.add(&BASE.add(x, x), x);
    let rhs = BASE.add(&BASE.sub(&x3, &three_x), &B);
    BASE.mul(y, y) == rhs
}

/// A Jacobian point `(X / Z^2, Y / Z^3)` in Montgomery form; `Z = 0` is the
/// identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Jacobian {
    x: [u64; 4],
    y: [u64; 4],
    z: [u64; 4],
}

impl Jacobian {
    /// The identity.
    pub const IDENTITY: Self = Self {
        x: [0; 4],
        y: [0; 4],
        z: [0; 4],
    };

    /// The Jacobian form of an affine point.
    #[must_use]
    pub fn from_affine(point: &Affine) -> Self {
        Self {
            x: BASE.montgomery_form(&point.x),
            y: BASE.montgomery_form(&point.y),
            z: BASE.montgomery_form(&[1, 0, 0, 0]),
        }
    }

    /// Whether this is the identity.
    #[must_use]
    pub fn is_identity(&self) -> bool {
        words_is_zero(&self.z)
    }

    /// `2 P` (`dbl-2001-b`, `a = -3`; the identity and `y = 0` give the
    /// identity).
    #[must_use]
    pub fn double(&self) -> Self {
        let f = &BASE;
        let delta = f.mont_mul(&self.z, &self.z);
        let gamma = f.mont_mul(&self.y, &self.y);
        let beta = f.mont_mul(&self.x, &gamma);
        let t0 = f.sub(&self.x, &delta);
        let t1 = f.add(&self.x, &delta);
        let t2 = f.mont_mul(&t0, &t1);
        let alpha = f.add(&f.add(&t2, &t2), &t2);
        let beta4 = f.add(&f.add(&beta, &beta), &f.add(&beta, &beta));
        let beta8 = f.add(&beta4, &beta4);
        let x3 = f.sub(&f.mont_mul(&alpha, &alpha), &beta8);
        let yz = f.add(&self.y, &self.z);
        let z3 = f.sub(&f.sub(&f.mont_mul(&yz, &yz), &gamma), &delta);
        let gamma2 = f.mont_mul(&gamma, &gamma);
        let gamma2_8 = {
            let two = f.add(&gamma2, &gamma2);
            let four = f.add(&two, &two);
            f.add(&four, &four)
        };
        let y3 = f.sub(&f.mont_mul(&alpha, &f.sub(&beta4, &x3)), &gamma2_8);
        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// `P + Q` for any points (variable time; `add-2007-bl`).
    #[must_use]
    #[allow(clippy::many_single_char_names)] // the formula's names
    pub fn add(&self, other: &Self) -> Self {
        if self.is_identity() {
            return *other;
        }
        if other.is_identity() {
            return *self;
        }
        let f = &BASE;
        let z1z1 = f.mont_mul(&self.z, &self.z);
        let z2z2 = f.mont_mul(&other.z, &other.z);
        let u1 = f.mont_mul(&self.x, &z2z2);
        let u2 = f.mont_mul(&other.x, &z1z1);
        let s1 = f.mont_mul(&f.mont_mul(&self.y, &other.z), &z2z2);
        let s2 = f.mont_mul(&f.mont_mul(&other.y, &self.z), &z1z1);
        if u1 == u2 {
            return if s1 == s2 {
                self.double()
            } else {
                Self::IDENTITY
            };
        }
        let h = f.sub(&u2, &u1);
        let h2 = f.add(&h, &h);
        let i = f.mont_mul(&h2, &h2);
        let j = f.mont_mul(&h, &i);
        let s_diff = f.sub(&s2, &s1);
        let r = f.add(&s_diff, &s_diff);
        let v = f.mont_mul(&u1, &i);
        let x3 = f.sub(&f.sub(&f.mont_mul(&r, &r), &j), &f.add(&v, &v));
        let s1j = f.mont_mul(&s1, &j);
        let y3 = f.sub(&f.mont_mul(&r, &f.sub(&v, &x3)), &f.add(&s1j, &s1j));
        let z_sum = f.add(&self.z, &other.z);
        let z3 = f.mont_mul(
            &f.sub(&f.sub(&f.mont_mul(&z_sum, &z_sum), &z1z1), &z2z2),
            &h,
        );
        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// `-P`.
    #[must_use]
    pub fn neg(&self) -> Self {
        Self {
            x: self.x,
            y: BASE.neg(&self.y),
            z: self.z,
        }
    }

    /// The affine form, or `None` for the identity.
    #[must_use]
    pub fn to_affine(self) -> Option<Affine> {
        if self.is_identity() {
            return None;
        }
        let f = &BASE;
        let z_inv = f.invert(&self.z);
        let z_inv2 = f.mont_mul(&z_inv, &z_inv);
        let z_inv3 = f.mont_mul(&z_inv2, &z_inv);
        Some(Affine {
            x: f.standard_form(&f.mont_mul(&self.x, &z_inv2)),
            y: f.standard_form(&f.mont_mul(&self.y, &z_inv3)),
        })
    }
}

/// The affine forms of many points with one inversion; `None` when any point
/// is the identity.
#[must_use]
pub fn batch_to_affine(points: &[Jacobian]) -> Option<Vec<Affine>> {
    let f = &BASE;
    if points.iter().any(Jacobian::is_identity) {
        return None;
    }
    let one = f.montgomery_form(&[1, 0, 0, 0]);
    let mut prefix = Vec::with_capacity(points.len());
    let mut acc = one;
    for point in points {
        prefix.push(acc);
        acc = f.mont_mul(&acc, &point.z);
    }
    let mut inverse = f.invert(&acc);
    let mut out = vec![
        Affine {
            x: [0; 4],
            y: [0; 4]
        };
        points.len()
    ];
    for index in (0..points.len()).rev() {
        let z_inv = f.mont_mul(&inverse, &prefix[index]);
        inverse = f.mont_mul(&inverse, &points[index].z);
        let z_inv2 = f.mont_mul(&z_inv, &z_inv);
        let z_inv3 = f.mont_mul(&z_inv2, &z_inv);
        out[index] = Affine {
            x: f.standard_form(&f.mont_mul(&points[index].x, &z_inv2)),
            y: f.standard_form(&f.mont_mul(&points[index].y, &z_inv3)),
        };
    }
    Some(out)
}

/// `[k] P` (double-and-add, variable time); `None` for the identity.
#[must_use]
pub fn mul(point: &Affine, k: &[u64; 4]) -> Option<Affine> {
    mul_jacobian(&Jacobian::from_affine(point), k).to_affine()
}

/// `[k] P` in Jacobian form (variable time).
#[must_use]
pub fn mul_jacobian(point: &Jacobian, k: &[u64; 4]) -> Jacobian {
    let mut acc = Jacobian::IDENTITY;
    for bit in (0..256).rev() {
        acc = acc.double();
        if (k[bit / 64] >> (bit % 64)) & 1 == 1 {
            acc = acc.add(point);
        }
    }
    acc
}

/// `[a] P + [b] Q` (variable time); `None` for the identity.
#[must_use]
pub fn mul_add(p: &Affine, a: &[u64; 4], q: &Affine, b: &[u64; 4]) -> Option<Affine> {
    mul_jacobian(&Jacobian::from_affine(p), a)
        .add(&mul_jacobian(&Jacobian::from_affine(q), b))
        .to_affine()
}

/// The KAGEMUSHA P-256 ECDSA verdict over a prehashed message (variable
/// time; a test oracle and reference).
///
/// `e` is the 256-bit big-endian integer of the SHA-256 output (reduced
/// mod `n` here). The signature `(r, s)` is accepted iff `1 <= r < n`,
/// `1 <= s <= (n - 1) / 2` (low-S), the key has canonical coordinates on the
/// curve, `R = [e / s] G + [r / s] Q` is not the identity and
/// `x(R) mod n = r`.
#[must_use]
pub fn verify_prehashed(e: &[u64; 4], r: &[u64; 4], s: &[u64; 4], key: &Affine) -> bool {
    if words_is_zero(r) || !words_lt(r, &N) {
        return false;
    }
    if words_is_zero(s) || words_cmp(s, &HALF_N) == Ordering::Greater {
        return false;
    }
    if !key.is_valid() {
        return false;
    }
    let e = ORDER.reduce_once(e);
    let w = ORDER.inverse(s);
    let u1 = ORDER.mul(&e, &w);
    let u2 = ORDER.mul(r, &w);
    mul_add(&Affine::GENERATOR, &u1, key, &u2)
        .is_some_and(|point| ORDER.reduce_once(&point.x) == *r)
}

/// The standard ECDSA verdict without the low-S rule (a test oracle).
#[must_use]
pub fn verify_prehashed_any_s(e: &[u64; 4], r: &[u64; 4], s: &[u64; 4], key: &Affine) -> bool {
    if words_is_zero(s) || !words_lt(s, &N) {
        return false;
    }
    let low = if words_cmp(s, &HALF_N) == Ordering::Greater {
        ORDER.neg(s)
    } else {
        *s
    };
    verify_prehashed(e, r, &low, key)
}

/// Big-endian bytes as little-endian words.
#[must_use]
pub fn words_from_be(bytes: &[u8; 32]) -> [u64; 4] {
    let mut out = [0_u64; 4];
    for (index, chunk) in bytes.chunks_exact(8).enumerate() {
        let mut word = [0_u8; 8];
        word.copy_from_slice(chunk);
        out[3 - index] = u64::from_be_bytes(word);
    }
    out
}

/// Little-endian words as big-endian bytes.
#[must_use]
pub fn words_to_be(words: &[u64; 4]) -> [u8; 32] {
    let mut out = [0_u8; 32];
    for (index, chunk) in out.chunks_exact_mut(8).enumerate() {
        chunk.copy_from_slice(&words[3 - index].to_be_bytes());
    }
    out
}

/// The limbs (`87, 87, 82` bits) of a 256-bit value.
#[must_use]
pub fn limbs_of(words: &[u64; 4]) -> [u128; LIMBS] {
    crate::ff::to_limbs(&Nat::from_words(*words)).unwrap_or([0; LIMBS])
}

// ---------------------------------------------------------------------------
// Window layouts.
// ---------------------------------------------------------------------------

/// The bit widths of the limbs of a proper value.
// The widths are 87 and 82: no truncation.
#[allow(clippy::cast_possible_truncation)]
pub const LIMB_WIDTHS: [u32; LIMBS] = [LIMB_BITS as u32, LIMB_BITS as u32, TOP_LIMB_BITS as u32];

/// One window of the per-limb digit decomposition of a proper scalar: bits
/// `[offset, offset + bits)` of limb `limb`, weight `2^position` with
/// `position = 87 limb + offset`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Window {
    /// The limb.
    pub limb: usize,
    /// The first bit within the limb.
    pub offset: u32,
    /// The width (the last window of a limb may be narrower).
    pub bits: u32,
    /// The absolute bit position of the window.
    pub position: u32,
}

/// The windows of width `width` of a proper scalar, in increasing position:
/// each limb is cut from its bit 0, and its last window holds the remaining
/// bits.
#[must_use]
pub fn windows(width: u32) -> Vec<Window> {
    let mut out = Vec::new();
    let mut base = 0_u32;
    for (limb, limb_bits) in LIMB_WIDTHS.iter().enumerate() {
        let mut offset = 0;
        while offset < *limb_bits {
            let bits = width.min(limb_bits - offset);
            out.push(Window {
                limb,
                offset,
                bits,
                position: base + offset,
            });
            offset += bits;
        }
        base += LIMB_WIDTHS[0];
    }
    out
}

/// `2^bits` as words (`bits < 256`).
#[must_use]
pub fn pow2_words(bits: u32) -> [u64; 4] {
    let mut out = [0_u64; 4];
    out[(bits / 64) as usize] = 1_u64 << (bits % 64);
    out
}

// ---------------------------------------------------------------------------
// Fixed-base tables.
// ---------------------------------------------------------------------------

/// The window tables of a fixed base `P` for windows of width `width`
/// (Orchard-style offsets): window `w < top` holds `(d + 2) 2^pos_w P` for
/// every digit `d < 2^bits_w`, and the top window holds
/// `d 2^pos_top P - 2 sum_{w < top} 2^pos_w P`, so the windows of the digits
/// of `k` sum to `[k] P`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixedTable {
    /// The windows (increasing position).
    pub windows: Vec<Window>,
    /// `entries[w][d]`.
    pub entries: Vec<Vec<Affine>>,
}

impl FixedTable {
    /// The table of `base` (`None` when an entry is the identity, which no
    /// valid base of prime order produces for these offsets).
    #[must_use]
    pub fn new(base: &Affine, width: u32) -> Option<Self> {
        let windows = windows(width);
        let top = windows.len().checked_sub(1)?;
        let mut jacobian = Vec::new();
        let mut weight_point = Jacobian::from_affine(base);
        let mut weight_position = 0_u32;
        let mut offset_sum = Jacobian::IDENTITY;
        for (index, window) in windows.iter().enumerate() {
            while weight_position < window.position {
                weight_point = weight_point.double();
                weight_position += 1;
            }
            let count = 1_usize << window.bits;
            if index < top {
                offset_sum = offset_sum.add(&weight_point);
                let mut entry = weight_point.double();
                for _ in 0..count {
                    jacobian.push(entry);
                    entry = entry.add(&weight_point);
                }
            } else {
                let mut entry = offset_sum.double().neg();
                for _ in 0..count {
                    jacobian.push(entry);
                    entry = entry.add(&weight_point);
                }
            }
        }
        let affine = batch_to_affine(&jacobian)?;
        let mut entries = Vec::with_capacity(windows.len());
        let mut cursor = 0;
        for window in &windows {
            let count = 1_usize << window.bits;
            entries.push(affine[cursor..cursor + count].to_vec());
            cursor += count;
        }
        Some(Self { windows, entries })
    }

    /// The number of entries (table rows).
    #[must_use]
    pub fn rows(&self) -> usize {
        self.entries.iter().map(Vec::len).sum()
    }
}

/// The integer `sum_w d_w 2^pos_w` of the window digits of `k` (the digits of
/// its limbs), as a check of a layout.
#[must_use]
pub fn window_digits(k: &[u64; 4], layout: &[Window]) -> Vec<u64> {
    let limbs = limbs_of(k);
    layout
        .iter()
        .map(|window| {
            let mask = (1_u128 << window.bits) - 1;
            // A window holds at most 8 bits.
            #[allow(clippy::cast_possible_truncation)]
            {
                ((limbs[window.limb] >> window.offset) & mask) as u64
            }
        })
        .collect()
}
