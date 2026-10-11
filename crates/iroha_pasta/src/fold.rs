//! Lockstep batch-affine GLV generator folding for the IPA prover.
//!
//! One IPA round replaces the generator vector `G` of length `2h` by
//! `G'[i] = G[i] + u * G[i + h]` for the round challenge `u`. The vendored
//! prover (`parallel_generator_collapse`) does this with an independent
//! constant-time double-and-add per point. The challenge is a public
//! Fiat-Shamir value, so variable time is acceptable, and the same scalar
//! multiplies every point:
//!
//! - the challenge is split once with GLV and recoded into width-5 wNAF;
//! - points are processed in blocks of up to 2048 lanes that run the same
//!   doubling/addition sequence in lockstep, so each step costs one shared
//!   field inversion for the whole block (batch-affine arithmetic);
//! - the endomorphism half reuses the odd-multiple table with `x` scaled by
//!   `beta`.
//!
//! The batch-affine formulas are incomplete. When any lane of a block hits an
//! exceptional case (a zero denominator: equal or opposite points, the
//! identity), that block is recomputed with the complete projective formulas.
//! The output is therefore exactly `G[i] + u * G[i + h]`, normalised to affine,
//! for every input, identical to the vendored collapse.

use crate::{CancellationToken, Cancelled};
use ff::Field;
use group::prime::PrimeCurveAffine;
use rayon::prelude::*;

use crate::curve::endo::wnaf_u128;
use crate::curve::{PastaAffine, PastaCurve};
use crate::field::PastaField;

/// Lanes per lockstep block.
pub const FOLD_BLOCK: usize = 2048;
/// wNAF window width of the challenge recoding.
const WIDTH: u32 = 5;
/// Odd multiples `1, 3, ..., 15` held per lane.
const TABLE: usize = 1 << (WIDTH - 2);

/// A fold challenge recoded once for all blocks.
#[derive(Clone, Debug)]
pub struct FoldChallenge<F> {
    scalar: F,
    /// wNAF digits of the first GLV half, sign folded in, least significant first.
    d1: Vec<i8>,
    /// wNAF digits of the second GLV half (applied through the endomorphism).
    d2: Vec<i8>,
}

impl<F: PastaField> FoldChallenge<F> {
    /// Recodes `scalar` for curve `C`. Returns `None` if the GLV split fails
    /// (impossible for the Pasta constants; callers then use the reference
    /// path).
    pub fn new<C: PastaCurve<ScalarExt = F>>(scalar: &F) -> Option<Self> {
        let d = C::glv_decompose(scalar)?;
        let signed = |digits: Vec<i8>, neg: bool| -> Vec<i8> {
            if neg {
                digits.into_iter().map(|x| -x).collect()
            } else {
                digits
            }
        };
        Some(Self {
            scalar: *scalar,
            d1: signed(wnaf_u128(d.k1, WIDTH), d.k1_neg),
            d2: signed(wnaf_u128(d.k2, WIDTH), d.k2_neg),
        })
    }

    /// The challenge scalar.
    pub fn scalar(&self) -> F {
        self.scalar
    }
}

/// Reusable per-block buffers.
struct Scratch<F> {
    den: Vec<F>,
    prefix: Vec<F>,
}

/// Inverts `den[..m]` in place; returns false if any entry is zero.
fn invert_all<F: PastaField>(den: &mut [F], prefix: &mut [F]) -> bool {
    let mut acc = F::ONE;
    for (d, p) in den.iter().zip(prefix.iter_mut()) {
        if d.is_zero_vartime() {
            return false;
        }
        *p = acc;
        acc *= d;
    }
    let Some(mut inv) = acc.invert_vartime() else {
        return false;
    };
    for (d, p) in den.iter_mut().zip(prefix.iter()).rev() {
        let t = inv * p;
        inv *= *d;
        *d = t;
    }
    true
}

/// `acc <- 2 acc` on every lane. Returns false on a zero denominator.
fn ba_double<F: PastaField>(ax: &mut [F], ay: &mut [F], s: &mut Scratch<F>) -> bool {
    let m = ax.len();
    for (d, y) in s.den.iter_mut().zip(ay.iter()) {
        *d = y.double();
    }
    if !invert_all(&mut s.den[..m], &mut s.prefix[..m]) {
        return false;
    }
    for ((x, y), inv) in ax.iter_mut().zip(ay.iter_mut()).zip(s.den.iter()) {
        let x1 = *x;
        let xx = x1.square();
        let lambda = (xx.double() + xx) * inv;
        let x3 = lambda.square() - x1.double();
        *y = lambda * (x1 - x3) - *y;
        *x = x3;
    }
    true
}

/// `acc <- acc + (+-)(px, py)` on every lane. Returns false on a zero
/// denominator.
fn ba_add<F: PastaField>(
    ax: &mut [F],
    ay: &mut [F],
    px: &[F],
    py: &[F],
    neg: bool,
    s: &mut Scratch<F>,
) -> bool {
    let m = ax.len();
    for k in 0..m {
        s.den[k] = px[k] - ax[k];
    }
    if !invert_all(&mut s.den[..m], &mut s.prefix[..m]) {
        return false;
    }
    for k in 0..m {
        let (x1, y1) = (ax[k], ay[k]);
        let y2 = if neg { -py[k] } else { py[k] };
        let lambda = (y2 - y1) * s.den[k];
        let x3 = lambda.square() - x1 - px[k];
        ay[k] = lambda * (x1 - x3) - y1;
        ax[k] = x3;
    }
    true
}

/// Folds one block in lockstep: `lo[i] <- lo[i] + u * hi[i]`. Returns false
/// (leaving `lo` untouched) on any exceptional case.
fn fold_block<C: PastaCurve>(
    lo: &mut [C::AffineExt],
    hi: &[C::AffineExt],
    ch: &FoldChallenge<C::ScalarExt>,
) -> bool {
    let m = lo.len();
    if lo
        .iter()
        .chain(hi.iter())
        .any(|p| bool::from(p.is_identity()))
    {
        return false;
    }
    let mut s = Scratch {
        den: vec![C::Base::ZERO; m],
        prefix: vec![C::Base::ZERO; m],
    };
    // Odd multiples P, 3P, ..., 15P of every hi lane.
    let mut tx = vec![vec![C::Base::ZERO; m]; TABLE];
    let mut ty = vec![vec![C::Base::ZERO; m]; TABLE];
    for (k, p) in hi.iter().enumerate() {
        tx[0][k] = p.x();
        ty[0][k] = p.y();
    }
    let mut dx = tx[0].clone();
    let mut dy = ty[0].clone();
    if !ba_double(&mut dx, &mut dy, &mut s) {
        return false;
    }
    for j in 1..TABLE {
        let (done_x, rest_x) = tx.split_at_mut(j);
        let (done_y, rest_y) = ty.split_at_mut(j);
        rest_x[0].copy_from_slice(&done_x[j - 1]);
        rest_y[0].copy_from_slice(&done_y[j - 1]);
        if !ba_add(&mut rest_x[0], &mut rest_y[0], &dx, &dy, false, &mut s) {
            return false;
        }
    }
    let beta = C::AffineExt::endo_beta();
    let tzx: Vec<Vec<C::Base>> = tx
        .iter()
        .map(|v| v.iter().map(|x| *x * beta).collect())
        .collect();

    let len = ch.d1.len().max(ch.d2.len());
    let mut ax = vec![C::Base::ZERO; m];
    let mut ay = vec![C::Base::ZERO; m];
    let mut started = false;
    for pos in (0..len).rev() {
        if started && !ba_double(&mut ax, &mut ay, &mut s) {
            return false;
        }
        for (digit, xs) in [
            (ch.d1.get(pos).copied().unwrap_or(0), &tx),
            (ch.d2.get(pos).copied().unwrap_or(0), &tzx),
        ] {
            if digit == 0 {
                continue;
            }
            let j = (usize::from(digit.unsigned_abs()) - 1) / 2;
            if started {
                if !ba_add(&mut ax, &mut ay, &xs[j], &ty[j], digit < 0, &mut s) {
                    return false;
                }
            } else {
                ax.copy_from_slice(&xs[j]);
                if digit < 0 {
                    for (a, y) in ay.iter_mut().zip(ty[j].iter()) {
                        *a = -*y;
                    }
                } else {
                    ay.copy_from_slice(&ty[j]);
                }
                started = true;
            }
        }
    }
    if !started {
        // u * hi = identity for every lane; lo is unchanged.
        return true;
    }
    let lx: Vec<C::Base> = lo.iter().map(PastaAffine::x).collect();
    let ly: Vec<C::Base> = lo.iter().map(PastaAffine::y).collect();
    if !ba_add(&mut ax, &mut ay, &lx, &ly, false, &mut s) {
        return false;
    }
    for (k, out) in lo.iter_mut().enumerate() {
        *out = crate::curve::affine_unchecked::<C::AffineExt>(ax[k], ay[k]);
    }
    true
}

/// Reference fold of one block with the complete formulas.
fn fold_block_reference<C: PastaCurve>(
    lo: &mut [C::AffineExt],
    hi: &[C::AffineExt],
    u: &C::ScalarExt,
) {
    let tmp: Vec<C> = lo
        .iter()
        .zip(hi.iter())
        .map(|(l, h)| l.to_curve() + h.to_curve().mul_vartime(u))
        .collect();
    C::batch_normalize(&tmp, lo);
}

/// Folds the generator vector in place: for `h = g.len() / 2`,
/// `g[i] <- g[i] + u * g[i + h]` for `i < h`. Returns `h`; the caller
/// truncates (as the vendored collapse does).
///
/// Runs blocks on the caller's Rayon pool. Public challenges only.
pub fn fold_generators_vartime<C: PastaCurve>(g: &mut [C::AffineExt], u: &C::ScalarExt) -> usize {
    match FoldChallenge::new::<C>(u) {
        Some(challenge) => fold_generators_with::<C>(g, &challenge),
        None => fold_generators_reference::<C>(g, u),
    }
}

/// [`fold_generators_vartime`] with a precomputed recoding of the challenge.
///
/// The challenge scalar is `challenge.scalar()`, used both by the lockstep
/// blocks and by the complete-formula fallback of exceptional blocks, so the
/// result cannot mix two challenges.
pub fn fold_generators_with<C: PastaCurve>(
    g: &mut [C::AffineExt],
    challenge: &FoldChallenge<C::ScalarExt>,
) -> usize {
    fold_blocks::<C>(g, &challenge.scalar(), Some(challenge), None).expect("no cancellation signal")
}

/// The fold with the complete projective formulas only (the fallback path of
/// [`fold_generators_vartime`]); the result is identical.
pub fn fold_generators_reference<C: PastaCurve>(g: &mut [C::AffineExt], u: &C::ScalarExt) -> usize {
    fold_blocks::<C>(g, u, None, None).expect("no cancellation signal")
}

/// Folds generators with an explicit operation signal.
///
/// # Errors
/// Returns [`Cancelled`] only after all Rayon tasks have joined. The caller
/// must discard the partially folded buffer after cancellation.
pub fn fold_generators_cancellable<C: PastaCurve>(
    g: &mut [C::AffineExt],
    u: &C::ScalarExt,
    cancellation: Option<&CancellationToken>,
) -> Result<usize, Cancelled> {
    CancellationToken::checkpoint(cancellation)?;
    let challenge = FoldChallenge::new::<C>(u);
    fold_blocks::<C>(g, u, challenge.as_ref(), cancellation)
}

/// Folds every block in lockstep when `challenge` (the recoding of `u`) is
/// given, else, and for exceptional blocks, with the complete formulas.
fn fold_blocks<C: PastaCurve>(
    g: &mut [C::AffineExt],
    u: &C::ScalarExt,
    challenge: Option<&FoldChallenge<C::ScalarExt>>,
    cancellation: Option<&CancellationToken>,
) -> Result<usize, Cancelled> {
    CancellationToken::checkpoint(cancellation)?;
    debug_assert!(challenge.is_none_or(|ch| ch.scalar() == *u));
    let half = g.len() / 2;
    if half == 0 {
        return Ok(0);
    }
    let (lo, rest) = g.split_at_mut(half);
    let hi = &rest[..half];
    let threads = rayon::current_num_threads().max(1);
    let block = FOLD_BLOCK.min(half.div_ceil(threads).max(64));
    lo.par_chunks_mut(block)
        .zip(hi.par_chunks(block))
        .for_each(|(l, h)| {
            if CancellationToken::checkpoint(cancellation).is_err() {
                return;
            }
            let done = challenge.is_some_and(|ch| fold_block::<C>(l, h, ch));
            if !done {
                fold_block_reference::<C>(l, h, u);
            }
        });
    CancellationToken::checkpoint(cancellation)?;
    Ok(half)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::{Ep, EpAffine, Eq, EqAffine};
    use crate::field::{Fp, Fq};
    use group::{Curve, Group};
    use rand_chacha::ChaCha20Rng;
    use rand_core_06::SeedableRng;

    fn reference<C: PastaCurve>(g: &[C::AffineExt], u: &C::ScalarExt) -> Vec<C::AffineExt> {
        let h = g.len() / 2;
        let tmp: Vec<C> = (0..h)
            .map(|i| g[i].to_curve() + g[i + h].to_curve() * *u)
            .collect();
        crate::curve::batch_normalize(&tmp)
    }

    #[test]
    fn fold_matches_reference_random() {
        let mut rng = ChaCha20Rng::seed_from_u64(12);
        let g: Vec<EqAffine> = (0..300).map(|_| Eq::random(&mut rng).to_affine()).collect();
        for u in [
            Fp::random(&mut rng),
            Fp::ONE,
            -Fp::ONE,
            Fp::ZERO,
            Fp::from(3u64),
        ] {
            let mut ours = g.clone();
            let h = fold_generators_vartime::<Eq>(&mut ours, &u);
            assert_eq!(h, 150);
            assert_eq!(&ours[..h], &reference::<Eq>(&g, &u)[..]);
        }
    }

    #[test]
    fn exceptional_lanes_fall_back() {
        let p = Ep::generator().to_affine();
        // lo = hi = P and u = 1: P + P needs a doubling; lo = -hi and u = 1 gives the identity.
        let mut g = vec![p, -p, p, p];
        let r = reference::<Ep>(&g, &Fq::ONE);
        fold_generators_vartime::<Ep>(&mut g, &Fq::ONE);
        assert_eq!(&g[..2], &r[..]);
        assert!(bool::from(g[1].is_identity()) || g[1] == r[1]);
        let mut with_identity = vec![EpAffine::default(), p];
        fold_generators_vartime::<Ep>(&mut with_identity, &Fq::from(5u64));
        assert_eq!(
            with_identity[0],
            (Ep::generator() * Fq::from(5u64)).to_affine()
        );
        let mut empty: Vec<EpAffine> = vec![p];
        assert_eq!(fold_generators_vartime::<Ep>(&mut empty, &Fq::ONE), 0);
    }

    #[test]
    fn precomputed_and_reference_entry_points_agree() {
        let mut rng = ChaCha20Rng::seed_from_u64(13);
        let mut g: Vec<EpAffine> = (0..200).map(|_| Ep::random(&mut rng).to_affine()).collect();
        // An exceptional lane forces one block onto the fallback, which must
        // use the challenge's own scalar.
        g[100 + 7] = g[7];
        let u = Fq::ONE;
        let expected = reference::<Ep>(&g, &u);
        let challenge = FoldChallenge::new::<Ep>(&u).unwrap();
        let mut with = g.clone();
        assert_eq!(fold_generators_with::<Ep>(&mut with, &challenge), 100);
        assert_eq!(&with[..100], &expected[..]);
        let mut plain = g.clone();
        assert_eq!(fold_generators_reference::<Ep>(&mut plain, &u), 100);
        assert_eq!(&plain[..100], &expected[..]);
        let random = Fq::random(&mut rng);
        let challenge = FoldChallenge::new::<Ep>(&random).unwrap();
        let mut with = g.clone();
        fold_generators_with::<Ep>(&mut with, &challenge);
        assert_eq!(&with[..100], &reference::<Ep>(&g, &random)[..]);
    }

    #[test]
    fn helpers() {
        let ch = FoldChallenge::new::<Eq>(&Fp::from(7u64)).unwrap();
        assert_eq!(ch.scalar(), Fp::from(7u64));
        let mut den = vec![Fq::from(2u64), Fq::ZERO];
        let mut pre = vec![Fq::ZERO; 2];
        assert!(!invert_all(&mut den, &mut pre));
    }
}
