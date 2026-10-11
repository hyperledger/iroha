//! Native references and witness generation of the Pasta ECC chip.
//!
//! Points are coordinate pairs in the chip encoding: an affine point is
//! `(x, y)` and the identity is `(0, 0)`. No Pasta point has `x = 0`
//! (`5` is not a square in either field), so `x = 0` identifies the
//! identity.
//!
//! Every function here is a pure function of its inputs (exact field
//! arithmetic, no environment). The witness generators branch on scalar
//! digits and on the exceptional cases of the group law, so their running
//! time depends on the values: they are for public data, the in-circuit
//! verifier's challenges and commitments, like the `*_vartime` routines of
//! [`iroha_pasta`] (whose GLV decomposition they use).

use ff::{Field, PrimeField, WithSmallOrderMulGroup};
use iroha_pasta::{PastaAffine, PastaCurve, PastaField};

/// An affine point in the chip encoding; the identity is `(0, 0)`.
pub type Coordinates<F> = (F, F);

/// Joint signed digits (iterations) of the GLV chain: one per bit of the
/// 128-bit digit words `B1`, `B2`.
pub const GLV_ITERATIONS: usize = 128;

/// Iterations `0..GLV_INCOMPLETE_ITERATIONS` use incomplete addition.
///
/// Iteration `j` is exceptional only if a nonzero lattice vector of
/// sup-norm at most `6 * 2^j - 1` exists (module documentation); the
/// sup-norm minimum of both Pasta GLV lattices is `2^126.21`, so
/// `j <= 123` is exception-free.
pub const GLV_INCOMPLETE_ITERATIONS: usize = 124;

/// Iterations computed with complete addition (the complete tail).
pub const GLV_COMPLETE_ITERATIONS: usize = GLV_ITERATIONS - GLV_INCOMPLETE_ITERATIONS;

/// Complete additions per GLV multiplication: two per complete iteration and
/// the final even-digit correction.
pub const GLV_COMPLETE_ADDITIONS: usize = 2 * GLV_COMPLETE_ITERATIONS + 1;

/// The row of the chain's `Y2` running sum that holds `floor(B2 / 2^63)`.
pub const GLV_B2_HIGH_PREFIX: usize = GLV_ITERATIONS - 63;

/// Bits per fixed-base window.
pub const FIXED_BASE_WINDOW_BITS: usize = 3;

/// Fixed-base windows: `85 * 3 = 255` bits cover every `lo + 2^128 hi`.
pub const FIXED_BASE_WINDOWS: usize = 85;

/// Points per fixed-base window.
pub const FIXED_BASE_WINDOW_POINTS: usize = 1 << FIXED_BASE_WINDOW_BITS;

/// The window whose running-sum entry is `floor(W / 2^129)`.
pub const FIXED_BASE_LINK_WINDOW: usize = 43;

/// The coordinates of `point` in the chip encoding.
#[must_use]
pub fn coordinates<C: PastaCurve>(point: &C) -> Coordinates<C::Base> {
    let affine = C::AffineExt::from(*point);
    (affine.x(), affine.y())
}

/// The point with chip-encoded `coordinates`, when they are on the curve or
/// `(0, 0)`.
#[must_use]
pub fn point<C: PastaCurve>(coordinates: Coordinates<C::Base>) -> Option<C> {
    Option::<C::AffineExt>::from(C::AffineExt::from_xy(coordinates.0, coordinates.1)).map(C::from)
}

/// Whether chip-encoded `coordinates` satisfy `y^2 = x^3 + 5` (the identity
/// `(0, 0)` does not).
#[must_use]
pub fn on_curve<C: PastaCurve>(coordinates: Coordinates<C::Base>) -> bool {
    let (x, y) = coordinates;
    y.square() == x.square() * x + C::b()
}

/// The base-field cube root of unity `beta`: `(beta x, y) = [zeta] (x, y)`.
#[must_use]
pub fn beta<C: PastaCurve>() -> C::Base {
    C::AffineExt::endo_beta()
}

/// The scalar-field cube root of unity `zeta` the endomorphism multiplies
/// by.
#[must_use]
pub fn zeta<C: PastaCurve>() -> C::ScalarExt {
    <C::ScalarExt as WithSmallOrderMulGroup<3>>::ZETA
}

/// `2^128` in `F`.
#[must_use]
pub fn two_pow_128<F: PastaField>() -> F {
    F::from_u128(1 << 127).double()
}

/// `2^bits` in `F` for `bits < 256`.
#[must_use]
pub fn two_pow<F: PastaField>(bits: usize) -> F {
    let mut limbs = [0_u64; 4];
    if let Some(limb) = limbs.get_mut(bits / 64) {
        *limb = 1 << (bits % 64);
    }
    F::from_raw_reduced(limbs)
}

/// The scalar `W mod r` of a scalar given as limbs `W = lo + 2^128 hi`.
#[must_use]
pub fn scalar_from_limbs<S: PastaField>(limbs: [u128; 2]) -> S {
    S::from_u128(limbs[0]) + S::from_u128(limbs[1]) * two_pow_128::<S>()
}

/// The canonical limbs `(lo, hi)` of a field element.
#[must_use]
pub fn limbs_of<S: PastaField>(value: &S) -> [u128; 2] {
    let limbs = value.to_canonical_limbs();
    [
        u128::from(limbs[0]) | (u128::from(limbs[1]) << 64),
        u128::from(limbs[2]) | (u128::from(limbs[3]) << 64),
    ]
}

/// Native reference of every variable-base multiplication of the chip:
/// `[W mod r] P` for `W = lo + 2^128 hi`.
#[must_use]
pub fn mul_native<C: PastaCurve>(point: &C, limbs: [u128; 2]) -> C {
    *point * scalar_from_limbs::<C::ScalarExt>(limbs)
}

/// Native reference of the Horner chain: `sum_i x^i P_i`.
#[must_use]
pub fn horner_native<C: PastaCurve>(points: &[C], x: [u128; 2]) -> C {
    let x = scalar_from_limbs::<C::ScalarExt>(x);
    points
        .iter()
        .rev()
        .fold(C::identity(), |acc, point| acc * x + *point)
}

/// The modulus of `S` as little-endian limbs.
fn modulus_limbs<S: PastaField>() -> [u64; 4] {
    let mut limbs = (-S::ONE).to_canonical_limbs();
    for limb in &mut limbs {
        let (sum, carry) = limb.overflowing_add(1);
        *limb = sum;
        if !carry {
            break;
        }
    }
    limbs
}

/// `a + b` for 256-bit integers whose sum fits 256 bits.
fn add_limbs(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    let mut out = [0_u64; 4];
    let mut carry = false;
    for ((out, a), b) in out.iter_mut().zip(a).zip(b) {
        let (sum, first) = a.overflowing_add(b);
        let (sum, second) = sum.overflowing_add(u64::from(carry));
        *out = sum;
        carry = first || second;
    }
    out
}

/// The low `bits` bits of a 256-bit integer.
fn low_bits(limbs: [u64; 4], bits: usize) -> [u64; 4] {
    let mut out = [0_u64; 4];
    for (index, (out, limb)) in out.iter_mut().zip(limbs).enumerate() {
        let start = 64 * index;
        if bits >= start + 64 {
            *out = limb;
        } else if bits > start {
            *out = limb & ((1_u64 << (bits - start)) - 1);
        }
    }
    out
}

/// The constants of the GLV split check (module documentation, "Scalar
/// split"), as elements of the circuit field `F`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SplitConstants<F> {
    /// `zeta mod p_N`.
    pub lambda: F,
    /// `r mod p_N`.
    pub modulus: F,
    /// `C1 = C0 + r mod p_N`, with `C0 = 2^128 (1 + zeta) mod r`.
    pub c1: F,
    /// `zeta mod 2^136`.
    pub lambda_136: F,
    /// `zeta mod 2^72`.
    pub lambda_72: F,
    /// `r mod 2^136`.
    pub modulus_136: F,
    /// `r mod 2^72`.
    pub modulus_72: F,
    /// `C1 mod 2^136`.
    pub c1_136: F,
}

impl<F: PastaField> SplitConstants<F> {
    /// The constants for the curve `C` whose base field is `F`.
    #[must_use]
    pub fn new<C: PastaCurve<Base = F>>() -> Self {
        let root = zeta::<C>();
        let lambda = root.to_canonical_limbs();
        let modulus = modulus_limbs::<C::ScalarExt>();
        let c0 = (two_pow_128::<C::ScalarExt>() * (C::ScalarExt::ONE + root)).to_canonical_limbs();
        let c1 = add_limbs(c0, modulus);
        Self {
            lambda: F::from_raw_reduced(lambda),
            modulus: F::from_raw_reduced(modulus),
            c1: F::from_raw_reduced(c1),
            lambda_136: F::from_raw_reduced(low_bits(lambda, 136)),
            lambda_72: F::from_raw_reduced(low_bits(lambda, 72)),
            modulus_136: F::from_raw_reduced(low_bits(modulus, 136)),
            modulus_72: F::from_raw_reduced(low_bits(modulus, 72)),
            c1_136: F::from_raw_reduced(low_bits(c1, 136)),
        }
    }
}

/// A GLV split in the chip's offset form: the digit words `B1, B2 < 2^128`
/// and the low bits `f1, f2` of `K_j = 2 B_j + f_j`, with
/// `W = (2^128 + K1) + zeta (2^128 + K2) (mod r)`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GlvHalves {
    /// `B1`.
    pub b1: u128,
    /// `f1`.
    pub f1: bool,
    /// `B2`.
    pub b2: u128,
    /// `f2`.
    pub f2: bool,
}

impl GlvHalves {
    /// The scalar the split stands for:
    /// `(2^128 + 2 B1 + f1) + zeta (2^128 + 2 B2 + f2)`.
    #[must_use]
    pub fn scalar<C: PastaCurve>(&self) -> C::ScalarExt {
        let half = |b: u128, f: bool| {
            two_pow_128::<C::ScalarExt>()
                + C::ScalarExt::from_u128(b).double()
                + if f {
                    C::ScalarExt::ONE
                } else {
                    C::ScalarExt::ZERO
                }
        };
        half(self.b1, self.f1) + zeta::<C>() * half(self.b2, self.f2)
    }

    /// The signed halves `k_j = K_j - 2^128` as `(negative, magnitude)`;
    /// `None` when a magnitude is `2^128` (`B_j = 0`, `f_j = 0`), the one
    /// value of the offset form outside `|k_j| < 2^128`.
    #[must_use]
    pub fn signed_halves(&self) -> Option<[(bool, u128); 2]> {
        let signed = |b: u128, f: bool| -> Option<(bool, u128)> {
            // K = 2 b + f; k = K - 2^128 = 2 (b - 2^127) + f.
            if b >= 1 << 127 {
                Some((false, ((b - (1 << 127)) << 1) | u128::from(f)))
            } else if b == 0 {
                // |k| = 2^128 - f fits only when f = 1.
                f.then_some((true, u128::MAX))
            } else {
                // |k| = 2 (2^127 - b) - f <= 2^128 - 2.
                Some((true, (((1_u128 << 127) - b) << 1) - u128::from(f)))
            }
        };
        Some([signed(self.b1, self.f1)?, signed(self.b2, self.f2)?])
    }
}

/// `K = 2^128 + k` as `(B, f)` with `K = 2 B + f`, for `|k| < 2^128`.
const fn offset_half(magnitude: u128, negative: bool) -> (u128, bool) {
    if negative && magnitude != 0 {
        // 2^128 - |k| fits a u128 for |k| >= 1.
        let offset = 0_u128.wrapping_sub(magnitude);
        (offset >> 1, offset & 1 == 1)
    } else {
        ((1 << 127) + (magnitude >> 1), magnitude & 1 == 1)
    }
}

/// The honest split of `scalar`: the GLV decomposition of
/// `scalar - 2^129 (1 + zeta)`, offset by `2^128` (so `K_j` lie in
/// `(2^126, 2^129 - 2^126)`).
///
/// Returns `None` only if the decomposition bound failed, which the Pasta
/// lattice constants exclude.
#[must_use]
pub fn glv_halves<C: PastaCurve>(scalar: &C::ScalarExt) -> Option<GlvHalves> {
    let shift = two_pow_128::<C::ScalarExt>().double() * (C::ScalarExt::ONE + zeta::<C>());
    let decomposition = C::glv_decompose(&(*scalar - shift))?;
    let (b1, f1) = offset_half(decomposition.k1, decomposition.k1_neg);
    let (b2, f2) = offset_half(decomposition.k2, decomposition.k2_neg);
    let halves = GlvHalves { b1, f1, b2, f2 };
    (halves.scalar::<C>() == *scalar).then_some(halves)
}

/// The split-check witness cells derived from `W` and the halves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SplitWitness<F> {
    /// `floor(B2 / 2^63)`.
    pub b2_high: F,
    /// `hi mod 2^8`.
    pub h0: F,
    /// `floor(hi / 2^8)`.
    pub h1: F,
    /// `u mod 2^64`, with `u r = K1 + zeta K2 + C1 - W`.
    pub u_low: F,
    /// `floor(u / 2^64)`.
    pub u_high: F,
    /// `v + 2^67`, with `2^136 v` the low-limb sum of the mod-`2^136` check.
    pub v_shifted: F,
}

/// `2^bits` as a `u128`-backed field element for `bits < 128`.
fn small_power<F: PastaField>(bits: u32) -> F {
    F::from_u128(1_u128 << bits)
}

/// `K = 2 B + f` in `F`.
fn half_field<F: PastaField>(b: u128, f: bool) -> F {
    F::from_u128(b).double() + if f { F::ONE } else { F::ZERO }
}

/// The split witness for `W = lo + 2^128 hi` and `halves`.
///
/// `u` and `v` are computed by field division (`u = num / r`,
/// `v = sum / 2^136`): when the halves represent `W mod r` both divisions
/// are exact integer divisions whose quotients are small, so the field
/// quotient is the integer. Otherwise the cells are garbage and the circuit
/// rejects them.
#[must_use]
pub fn split_witness<C: PastaCurve>(limbs: [u128; 2], halves: &GlvHalves) -> SplitWitness<C::Base> {
    split_witness_fields::<C>(
        limbs,
        [
            half_field(halves.b1, halves.f1),
            half_field(halves.b2, halves.f2),
        ],
        C::Base::from_u128(halves.b2 >> 63),
    )
}

/// [`split_witness`] from `K1, K2` and `floor(B2 / 2^63)` as field
/// elements, so tests can lay out splits whose halves leave the range.
#[must_use]
pub fn split_witness_fields<C: PastaCurve>(
    limbs: [u128; 2],
    k: [C::Base; 2],
    b2_high: C::Base,
) -> SplitWitness<C::Base> {
    let constants = SplitConstants::<C::Base>::new::<C>();
    let [lo, hi] = limbs;
    let [k1, k2] = k;
    let w = C::Base::from_u128(lo) + C::Base::from_u128(hi) * two_pow_128::<C::Base>();
    let numerator = k1 + constants.lambda * k2 + constants.c1 - w;
    let u = numerator * constants.modulus.invert().unwrap_or(C::Base::ZERO);
    let [u_low, u_high] = {
        let limbs = u.to_canonical_limbs();
        [
            C::Base::from(limbs[0]),
            C::Base::from(limbs[1]) + C::Base::from(limbs[2]) * two_pow::<C::Base>(64),
        ]
    };
    let two_64 = two_pow::<C::Base>(64);
    let k2_low = k2 - two_64 * b2_high;
    let h0 = C::Base::from_u128(hi & 0xff);
    let sum = k1
        + constants.lambda_136 * k2_low
        + two_64 * constants.lambda_72 * b2_high
        + constants.c1_136
        - C::Base::from_u128(lo)
        - two_pow_128::<C::Base>() * h0
        - constants.modulus_136 * u_low
        - two_64 * constants.modulus_72 * u_high;
    let v = sum * two_pow::<C::Base>(136).invert().unwrap_or(C::Base::ZERO);
    SplitWitness {
        b2_high,
        h0,
        h1: C::Base::from_u128(hi >> 8),
        u_low,
        u_high,
        v_shifted: v + small_power::<C::Base>(67),
    }
}

/// The witness of one complete addition (the halo2 book's complete addition
/// with its inverse witnesses).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddWitness<F> {
    /// The slope (the tangent slope when `x_p = x_q`, zero when both are the
    /// identity).
    pub lambda: F,
    /// `inv0(x_q - x_p)`.
    pub alpha: F,
    /// `inv0(x_p)`.
    pub beta: F,
    /// `inv0(x_q)`.
    pub gamma: F,
    /// `inv0(y_q + y_p)` when `x_q = x_p`, else zero.
    pub delta: F,
    /// `p + q`.
    pub output: Coordinates<F>,
}

/// `inv0(x)`: the inverse, or zero for zero.
fn inv0<F: PastaField>(x: F) -> F {
    x.invert().unwrap_or(F::ZERO)
}

/// The witness of the complete addition `p + q` of chip-encoded points on
/// the curve (or the identity).
#[must_use]
pub fn complete_add_witness<F: PastaField>(p: Coordinates<F>, q: Coordinates<F>) -> AddWitness<F> {
    let ((x_p, y_p), (x_q, y_q)) = (p, q);
    let d = x_q - x_p;
    let s = y_q + y_p;
    let alpha = inv0(d);
    let beta = inv0(x_p);
    let gamma = inv0(x_q);
    let same_x = bool::from(d.is_zero());
    let delta = if same_x { inv0(s) } else { F::ZERO };
    let lambda = if !same_x {
        (y_q - y_p) * alpha
    } else if bool::from(y_p.is_zero()) {
        F::ZERO
    } else {
        (x_p.square() * F::from(3)) * inv0(y_p.double())
    };
    let output = if bool::from(x_p.is_zero()) {
        q
    } else if bool::from(x_q.is_zero()) {
        p
    } else if same_x && bool::from(s.is_zero()) {
        (F::ZERO, F::ZERO)
    } else {
        let x_r = lambda.square() - x_p - x_q;
        (x_r, lambda * (x_p - x_r) - y_p)
    };
    AddWitness {
        lambda,
        alpha,
        beta,
        gamma,
        delta,
        output,
    }
}

/// The complete-addition polynomials of the chip's `q_add` gate, evaluated
/// natively; all zero exactly when the witness is accepted.
#[must_use]
pub fn complete_add_residues<F: PastaField>(
    p: Coordinates<F>,
    q: Coordinates<F>,
    witness: &AddWitness<F>,
) -> Vec<F> {
    let ((x_p, y_p), (x_q, y_q)) = (p, q);
    let AddWitness {
        lambda,
        alpha,
        beta,
        gamma,
        delta,
        output: (x_r, y_r),
    } = *witness;
    let three = F::from(3);
    let d = x_q - x_p;
    let s = y_q + y_p;
    let not_d = F::ONE - d * alpha;
    let not_p = F::ONE - x_p * beta;
    let not_q = F::ONE - x_q * gamma;
    let not_s = F::ONE - s * delta;
    let secant_x = lambda.square() - x_p - x_q - x_r;
    let secant_y = lambda * (x_p - x_r) - y_p - y_r;
    let both = x_p * x_q;
    let neither = not_d - s * delta;
    vec![
        d * (d * lambda - (y_q - y_p)),
        not_d * (y_p.double() * lambda - three * x_p.square()),
        both * d * secant_x,
        both * d * secant_y,
        both * s * secant_x,
        both * s * secant_y,
        not_p * (x_r - x_q),
        not_p * (y_r - y_q),
        not_q * (x_r - x_p),
        not_q * (y_r - y_p),
        neither * x_r,
        neither * y_r,
        d * not_d,
        alpha * not_d,
        x_p * not_p,
        beta * not_p,
        x_q * not_q,
        gamma * not_q,
        d * delta,
        not_d * s * not_s,
        delta * not_s,
        not_p * not_q * lambda,
    ]
}

/// One incomplete step `(A + T) + A` of the chain, or `None` on an
/// exceptional case.
fn double_and_add<F: PastaField>(
    acc: Coordinates<F>,
    t: Coordinates<F>,
) -> Option<(F, F, Coordinates<F>)> {
    let ((x_a, y_a), (x_t, y_t)) = (acc, t);
    let lambda_1 = (y_a - y_t) * Option::<F>::from((x_a - x_t).invert())?;
    let x_r = lambda_1.square() - x_a - x_t;
    let lambda_2 = y_a.double() * Option::<F>::from((x_a - x_r).invert())? - lambda_1;
    let x_next = lambda_2.square() - x_a - x_r;
    let y_next = lambda_2 * (x_a - x_next) - y_a;
    Some((lambda_1, lambda_2, (x_next, y_next)))
}

/// The joint digit point `T = (2 b1 - 1) P + (2 b2 - 1) phi(P)`, from
/// `S+ = P + phi(P)` and `S- = P - phi(P)`.
fn joint_point<F: PastaField>(
    b1: bool,
    b2: bool,
    plus: Coordinates<F>,
    minus: Coordinates<F>,
) -> Coordinates<F> {
    let (x, y) = if b1 == b2 { plus } else { minus };
    (x, if b1 { y } else { -y })
}

/// The witness of one GLV chain (module documentation, "Layout").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainWitness<F> {
    /// Whether the guarded input was the identity.
    pub is_identity: bool,
    /// `inv0(x_in)` (guard).
    pub inverse: F,
    /// The non-identity base the chain multiplies (the generator when the
    /// guarded input is the identity).
    pub base: Coordinates<F>,
    /// The tangent slope of `2P`.
    pub lambda_double: F,
    /// The slope of `P - phi(P)`.
    pub lambda_minus: F,
    /// `S- = P - phi(P)`.
    pub minus: Coordinates<F>,
    /// The accumulator before each incomplete iteration and after the last
    /// (`GLV_INCOMPLETE_ITERATIONS + 1` points).
    pub acc: Vec<Coordinates<F>>,
    /// `(lambda_1, lambda_2)` of each incomplete iteration.
    pub lambdas: Vec<(F, F)>,
    /// The running sums `Y1_j, Y2_j = floor(B / 2^(128 - j))`,
    /// `j = 0..=128`.
    pub running: [Vec<F>; 2],
    /// The digit points of the complete iterations.
    pub tail_points: Vec<Coordinates<F>>,
    /// The complete additions in layout order.
    pub adds: Vec<AddWitness<F>>,
    /// `-E`, the even-digit correction.
    pub minus_e: Coordinates<F>,
    /// The (guarded) result.
    pub output: Coordinates<F>,
}

/// The bit of `value` at `index` (`index < 128`).
const fn bit(value: u128, index: usize) -> bool {
    (value >> index) & 1 == 1
}

/// `floor(b / 2^(128 - j))` for `j <= 128`.
const fn prefix(b: u128, j: usize) -> u128 {
    if j == 0 { 0 } else { b >> (GLV_ITERATIONS - j) }
}

/// The chain witness for the chip-encoded `input` (the identity is guarded:
/// the generator is multiplied and the result replaced by the identity) and
/// `halves`.
///
/// Returns `None` if an incomplete step met an exceptional case, which the
/// lattice bound excludes for every on-curve input.
#[must_use]
pub fn chain_witness<C: PastaCurve>(
    input: Coordinates<C::Base>,
    halves: &GlvHalves,
) -> Option<ChainWitness<C::Base>> {
    let beta = beta::<C>();
    let is_identity = bool::from(input.0.is_zero());
    let inverse = inv0(input.0);
    let base = if is_identity {
        coordinates(&C::generator())
    } else {
        input
    };
    let (x, y) = base;
    let lambda_double =
        x.square() * C::Base::from(3) * Option::<C::Base>::from(y.double().invert())?;
    let x_2 = lambda_double.square() - x.double();
    let y_2 = lambda_double * (x - x_2) - y;
    let lambda_minus = y.double() * Option::<C::Base>::from(((C::Base::ONE - beta) * x).invert())?;
    let x_minus = lambda_minus.square() - (C::Base::ONE + beta) * x;
    let minus = (x_minus, lambda_minus * (x - x_minus) - y);
    let plus = (beta.square() * x, -y);
    let digits = |j: usize| {
        let index = GLV_ITERATIONS - 1 - j;
        (bit(halves.b1, index), bit(halves.b2, index))
    };
    let mut acc = vec![(beta.square() * x_2, -y_2)];
    let mut lambdas = Vec::with_capacity(GLV_INCOMPLETE_ITERATIONS);
    for j in 0..GLV_INCOMPLETE_ITERATIONS {
        let (b1, b2) = digits(j);
        let current = *acc.last()?;
        let (lambda_1, lambda_2, next) = double_and_add(current, joint_point(b1, b2, plus, minus))?;
        lambdas.push((lambda_1, lambda_2));
        acc.push(next);
    }
    let running = [halves.b1, halves.b2].map(|b| {
        (0..=GLV_ITERATIONS)
            .map(|j| C::Base::from_u128(prefix(b, j)))
            .collect::<Vec<_>>()
    });
    let tail_points: Vec<_> = (GLV_INCOMPLETE_ITERATIONS..GLV_ITERATIONS)
        .map(|j| {
            let (b1, b2) = digits(j);
            joint_point(b1, b2, plus, minus)
        })
        .collect();
    let mut adds = Vec::with_capacity(GLV_COMPLETE_ADDITIONS);
    let mut current = *acc.last()?;
    for (index, t) in tail_points.iter().enumerate() {
        // Layout order: the first iteration adds `A + T` with `A` copied
        // from the incomplete chain; later ones add `T + A` with `A` in place.
        let first = if index == 0 {
            complete_add_witness(current, *t)
        } else {
            complete_add_witness(*t, current)
        };
        adds.push(first);
        let doubled = complete_add_witness(current, first.output);
        adds.push(doubled);
        current = doubled.output;
    }
    let (e1, e2) = (!halves.f1, !halves.f2);
    let x_e = x * if e1 && e2 {
        beta.square()
    } else if e2 {
        beta
    } else if e1 {
        C::Base::ONE
    } else {
        C::Base::ZERO
    };
    let y_e = match (e1, e2) {
        (true, true) => -y,
        (false, false) => C::Base::ZERO,
        _ => y,
    };
    let minus_e = (x_e, -y_e);
    let correction = complete_add_witness(minus_e, current);
    adds.push(correction);
    let output = if is_identity {
        (C::Base::ZERO, C::Base::ZERO)
    } else {
        correction.output
    };
    Some(ChainWitness {
        is_identity,
        inverse,
        base,
        lambda_double,
        lambda_minus,
        minus,
        acc,
        lambdas,
        running,
        tail_points,
        adds,
        minus_e,
        output,
    })
}

/// The table of one fixed base: per window, the eight window points and
/// the multilinear coefficients of their coordinates in the window bits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixedBaseTable<F> {
    /// `points[i][k]`: window `i < 84` holds `[(k + 2) 8^i] B`; window 84
    /// holds `[k 8^84 - 2 sum_{j<84} 8^j] B`.
    pub points: Vec<[Coordinates<F>; FIXED_BASE_WINDOW_POINTS]>,
    /// Multilinear coefficients of `x` (index = bit mask of `b0, b1, b2`).
    pub x_coefficients: Vec<[F; FIXED_BASE_WINDOW_POINTS]>,
    /// Multilinear coefficients of `y`.
    pub y_coefficients: Vec<[F; FIXED_BASE_WINDOW_POINTS]>,
}

/// The multilinear (Moebius) coefficients `c_S` with
/// `values[k] = sum_{S subset of bits(k)} c_S`.
#[must_use]
pub fn multilinear_coefficients<F: PastaField>(
    values: [F; FIXED_BASE_WINDOW_POINTS],
) -> [F; FIXED_BASE_WINDOW_POINTS] {
    let mut coefficients = values;
    for bit in 0..FIXED_BASE_WINDOW_BITS {
        for mask in 0..FIXED_BASE_WINDOW_POINTS {
            if mask & (1 << bit) != 0 {
                let lower = coefficients[mask ^ (1 << bit)];
                coefficients[mask] -= lower;
            }
        }
    }
    coefficients
}

/// Evaluates multilinear coefficients at the bits of `k`.
#[must_use]
pub fn multilinear_eval<F: PastaField>(
    coefficients: &[F; FIXED_BASE_WINDOW_POINTS],
    k: usize,
) -> F {
    coefficients
        .iter()
        .enumerate()
        .filter(|(mask, _)| mask & !k == 0)
        .map(|(_, c)| *c)
        .sum()
}

/// The window multiples of `base`: `(k + 2) 8^i` for `i < 84` and
/// `k 8^84 - 2 sum_{j<84} 8^j` for the last window.
fn window_scalar<S: PastaField>(window: usize, k: usize) -> S {
    let eight = S::from(8);
    let power = |i: usize| (0..i).fold(S::ONE, |acc, _| acc * eight);
    let k = S::from(u64::try_from(k).unwrap_or(0));
    if window + 1 < FIXED_BASE_WINDOWS {
        (k + S::from(2)) * power(window)
    } else {
        let offset: S = (0..window).map(|j| power(j).double()).sum();
        k * power(window) - offset
    }
}

/// The fixed-base table of `base` (`None` for the identity).
#[must_use]
pub fn fixed_base_table<C: PastaCurve>(base: &C) -> Option<FixedBaseTable<C::Base>> {
    if bool::from(base.is_identity()) {
        return None;
    }
    let mut points = Vec::with_capacity(FIXED_BASE_WINDOWS);
    let mut x_coefficients = Vec::with_capacity(FIXED_BASE_WINDOWS);
    let mut y_coefficients = Vec::with_capacity(FIXED_BASE_WINDOWS);
    for window in 0..FIXED_BASE_WINDOWS {
        let row: [Coordinates<C::Base>; FIXED_BASE_WINDOW_POINTS] = core::array::from_fn(|k| {
            coordinates(&(*base * window_scalar::<C::ScalarExt>(window, k)))
        });
        x_coefficients.push(multilinear_coefficients(row.map(|(x, _)| x)));
        y_coefficients.push(multilinear_coefficients(row.map(|(_, y)| y)));
        points.push(row);
    }
    Some(FixedBaseTable {
        points,
        x_coefficients,
        y_coefficients,
    })
}

/// The witness of one fixed-base multiplication.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixedBaseWitness<F> {
    /// The window digits `k_i`.
    pub windows: Vec<usize>,
    /// The running sums `z_i = floor(W / 8^i)`, `i = 0..85`.
    pub running: Vec<F>,
    /// `A_i = sum_{j<i} T_j` for `i = 1..=84` (index `i - 1`).
    pub acc: Vec<Coordinates<F>>,
    /// The slopes of the incomplete additions of windows `1..=83`.
    pub lambdas: Vec<F>,
    /// The final complete addition `A_84 + T_84`.
    pub last: AddWitness<F>,
    /// `hi mod 2`.
    pub h0: bool,
}

/// `floor(W / 2^shift)` as a field element, for `W = lo + 2^128 hi`.
fn shifted<F: PastaField>(limbs: [u128; 2], shift: usize) -> F {
    let [lo, hi] = limbs;
    if shift >= 128 {
        F::from_u128(hi >> (shift - 128))
    } else if shift == 0 {
        F::from_u128(lo) + F::from_u128(hi) * two_pow_128::<F>()
    } else {
        F::from_u128(lo >> shift) + F::from_u128(hi) * two_pow::<F>(128 - shift)
    }
}

/// The 3-bit window `i` of `W = lo + 2^128 hi`.
fn window_digit(limbs: [u128; 2], window: usize) -> usize {
    let [lo, hi] = limbs;
    let start = FIXED_BASE_WINDOW_BITS * window;
    let bits = |value: u128, from: usize| -> u128 { if from >= 128 { 0 } else { value >> from } };
    let word = if start >= 128 {
        bits(hi, start - 128)
    } else {
        bits(lo, start)
            | hi.checked_shl(u32::try_from(128 - start).unwrap_or(128))
                .unwrap_or(0)
    };
    usize::try_from(word & 0b111).unwrap_or(0)
}

/// The fixed-base witness for `W = lo + 2^128 hi` against `table`, or
/// `None` on an exceptional incomplete step (excluded by the offsets).
#[must_use]
pub fn fixed_base_witness<F: PastaField>(
    table: &FixedBaseTable<F>,
    limbs: [u128; 2],
) -> Option<FixedBaseWitness<F>> {
    let windows: Vec<usize> = (0..FIXED_BASE_WINDOWS)
        .map(|window| window_digit(limbs, window))
        .collect();
    let running = (0..FIXED_BASE_WINDOWS)
        .map(|window| shifted::<F>(limbs, FIXED_BASE_WINDOW_BITS * window))
        .collect();
    let point = |window: usize| -> Option<Coordinates<F>> {
        table
            .points
            .get(window)?
            .get(*windows.get(window)?)
            .copied()
    };
    let mut acc = vec![point(0)?];
    let mut lambdas = Vec::with_capacity(FIXED_BASE_WINDOWS - 2);
    for window in 1..FIXED_BASE_WINDOWS - 1 {
        let (x_a, y_a) = *acc.last()?;
        let (x_t, y_t) = point(window)?;
        let lambda = (y_a - y_t) * Option::<F>::from((x_a - x_t).invert())?;
        let x_next = lambda.square() - x_a - x_t;
        acc.push((x_next, lambda * (x_a - x_next) - y_a));
        lambdas.push(lambda);
    }
    let last = complete_add_witness(*acc.last()?, point(FIXED_BASE_WINDOWS - 1)?);
    Some(FixedBaseWitness {
        windows,
        running,
        acc,
        lambdas,
        last,
        h0: limbs[1] & 1 == 1,
    })
}

#[cfg(test)]
mod tests {
    use iroha_pasta::{Ep, Eq, Fp, Fq};
    use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

    use super::*;

    fn random_scalar<S: PastaField>(rng: &mut ChaCha20Rng) -> S {
        S::random(rng)
    }

    fn halves_round_trip<C: PastaCurve>() {
        let mut rng = ChaCha20Rng::seed_from_u64(11);
        let edges = [
            C::ScalarExt::ZERO,
            C::ScalarExt::ONE,
            -C::ScalarExt::ONE,
            zeta::<C>(),
            two_pow_128::<C::ScalarExt>(),
        ];
        for scalar in edges
            .into_iter()
            .chain((0..200).map(|_| random_scalar(&mut rng)))
        {
            let halves = glv_halves::<C>(&scalar).expect("split");
            assert_eq!(halves.scalar::<C>(), scalar);
            for (negative, magnitude) in halves.signed_halves().expect("|k| < 2^128") {
                // |k| < 2^127 + 2^126 for the Babai split.
                assert!(
                    magnitude < (1 << 127) + (1 << 126),
                    "{negative} {magnitude}"
                );
            }
        }
    }

    #[test]
    fn honest_halves_reconstruct_the_scalar() {
        halves_round_trip::<Ep>();
        halves_round_trip::<Eq>();
    }

    #[test]
    fn signed_halves_match_offset_form() {
        let halves = GlvHalves {
            b1: 1 << 127,
            f1: true,
            b2: (1 << 127) - 1,
            f2: false,
        };
        assert_eq!(halves.signed_halves(), Some([(false, 1), (true, 2)]));
        let low = GlvHalves {
            b1: 0,
            f1: true,
            b2: u128::MAX,
            f2: true,
        };
        assert_eq!(
            low.signed_halves(),
            Some([(true, u128::MAX), (false, u128::MAX)])
        );
        assert_eq!(GlvHalves::default().signed_halves(), None);
        assert_eq!(offset_half(0, true), (1 << 127, false));
        assert_eq!(offset_half(3, true), ((0_u128.wrapping_sub(3)) >> 1, true));
    }

    #[test]
    fn helpers_are_exact() {
        assert_eq!(two_pow::<Fp>(136), two_pow_128::<Fp>() * Fp::from(256));
        assert_eq!(two_pow::<Fq>(0), Fq::ONE);
        assert_eq!(modulus_limbs::<Fq>(), {
            let mut limbs = (-Fq::ONE).to_canonical_limbs();
            limbs[0] += 1;
            limbs
        });
        assert_eq!(low_bits([u64::MAX; 4], 72), [u64::MAX, 0xff, 0, 0]);
        assert_eq!(low_bits([u64::MAX; 4], 256), [u64::MAX; 4]);
        assert_eq!(add_limbs([u64::MAX, 0, 0, 0], [1, 0, 0, 0]), [0, 1, 0, 0]);
        assert_eq!(limbs_of(&Fp::from_u128(5)), [5, 0]);
        assert_eq!(
            scalar_from_limbs::<Fq>([3, 1]),
            Fq::from(3) + two_pow_128::<Fq>()
        );
        assert_eq!(prefix(u128::MAX, 128), u128::MAX);
        assert_eq!(prefix(u128::MAX, 1), 1);
        assert_eq!(prefix(u128::MAX, 0), 0);
        let limbs = [0x0123_4567_89ab_cdef_0123_4567_89ab_cdef, 0x7fff_0000_1234];
        for window in 0..FIXED_BASE_WINDOWS {
            let z: Fp = shifted(limbs, 3 * window);
            let next: Fp = shifted(limbs, 3 * window + 3);
            let k = window_digit(limbs, window);
            assert_eq!(
                z,
                next * Fp::from(8) + Fp::from(u64::try_from(k).expect("k"))
            );
        }
    }

    #[test]
    fn multilinear_coefficients_interpolate() {
        let values: [Fp; 8] =
            core::array::from_fn(|k| Fp::from(u64::try_from(k * k + 3).expect("k")));
        let coefficients = multilinear_coefficients(values);
        for (k, value) in values.iter().enumerate() {
            assert_eq!(multilinear_eval(&coefficients, k), *value);
        }
    }

    fn add_cases<C: PastaCurve>() {
        let g = C::generator();
        let h = g.double() + g;
        let cases = [
            (C::identity(), C::identity()),
            (C::identity(), g),
            (g, C::identity()),
            (g, g),
            (g, -g),
            (g, h),
            (h, g.endo()),
            (g, -g.endo()),
        ];
        for (p, q) in cases {
            let (pc, qc) = (coordinates(&p), coordinates(&q));
            let witness = complete_add_witness(pc, qc);
            assert_eq!(witness.output, coordinates(&(p + q)));
            assert!(
                complete_add_residues(pc, qc, &witness)
                    .iter()
                    .all(|r| bool::from(r.is_zero()))
            );
            // A wrong output is rejected by some polynomial.
            let mut wrong = witness;
            wrong.output.1 += C::Base::ONE;
            assert!(
                complete_add_residues(pc, qc, &wrong)
                    .iter()
                    .any(|r| !bool::from(r.is_zero()))
            );
        }
    }

    #[test]
    fn complete_add_witness_matches_group_law() {
        add_cases::<Ep>();
        add_cases::<Eq>();
    }

    fn chain_cases<C: PastaCurve>() {
        let mut rng = ChaCha20Rng::seed_from_u64(5);
        for _ in 0..8 {
            let point = C::generator() * random_scalar::<C::ScalarExt>(&mut rng);
            let scalar = random_scalar::<C::ScalarExt>(&mut rng);
            let halves = glv_halves::<C>(&scalar).expect("split");
            let witness = chain_witness::<C>(coordinates(&point), &halves).expect("chain");
            assert_eq!(witness.output, coordinates(&(point * scalar)));
            let guarded =
                chain_witness::<C>((C::Base::ZERO, C::Base::ZERO), &halves).expect("guard");
            assert_eq!(guarded.output, (C::Base::ZERO, C::Base::ZERO));
        }
    }

    #[test]
    fn chain_witness_matches_scalar_multiplication() {
        chain_cases::<Ep>();
        chain_cases::<Eq>();
    }

    fn fixed_base_cases<C: PastaCurve>() {
        let base = C::generator().double();
        let table = fixed_base_table(&base).expect("table");
        for (window, row) in table.points.iter().enumerate() {
            for (k, point) in row.iter().enumerate() {
                assert!(on_curve::<C>(*point), "window {window} k {k}");
            }
        }
        for limbs in [[0, 0], [1, 0], [u128::MAX, (1 << 127) - 1], [12345, 678]] {
            let witness = fixed_base_witness(&table, limbs).expect("fixed base");
            assert_eq!(witness.last.output, coordinates(&mul_native(&base, limbs)));
        }
        assert!(fixed_base_table(&C::identity()).is_none());
    }

    #[test]
    fn fixed_base_witness_matches_scalar_multiplication() {
        fixed_base_cases::<Ep>();
        fixed_base_cases::<Eq>();
    }
}
