//! Vector commitments and verifier-side linear combinations of points.
//!
//! A commitment to `a` of length `m <= n` is `sum_{i<m} a_i B_i + blind * W`,
//! where `B` is `g` (coefficient form, [`commit`]) or `g_lagrange`
//! (evaluation form, [`commit_lagrange`]). The vendored `Blind::default()` is
//! one, so key-generation commitments are `... + W` ([`DEFAULT_BLIND`]); this
//! keeps every commitment of an all-zero column away from the identity.
//!
//! [`Secrecy`] selects the MSM posture of the prover's commitments:
//! witness-dependent scalars use [`iroha_pasta::msm::msm_secret`] and
//! constant-time scalar multiplication of `W`; public data (fixed columns,
//! instances) uses the variable-time paths. Both return the same point.
//!
//! # The verifier MSM (S10)
//!
//! Every verifier-side combination ([`Msm::evaluate`], so the instance
//! commitments, the opening equation and the batch equation, plus the
//! folded generator, `decide` and `batch_decide`) runs [`msm_complete`]: a
//! portable Pippenger whose buckets, running sums and window combination use
//! only the complete projective formulas (complete mixed addition of the
//! affine bases, complete addition and doubling). It has no batch-affine or
//! incomplete-formula path, so prover-chosen bases (`L_j`, `R_j`, `G`,
//! commitments) never meet an exceptional case, and no failure: the memory
//! budget only changes its window and wave sizes, never its result. The
//! optimized batch-affine `iroha_pasta::msm::msm_public` stays prover-only
//! until it is audited and differentially qualified for consensus.
//!
//! The scalars are public, so [`msm_complete`] splits each one with the GLV
//! endomorphism (`s = k1 + k2 ZETA`, `|k1|, |k2| < 2^128`, so `s B = k1 B +
//! k2 phi(B)` with `phi(x, y) = (beta x, y)`) and recodes the halves into
//! signed base-`2^c` digits: half the buckets of unsigned digits, and the
//! negated affine base for a negative digit (free, and still a complete mixed
//! addition). The scalar recoding changes no formula and no result; when a
//! split were unavailable (excluded by the Pasta constants) the unsigned
//! full-width windows run instead.
//!
//! The split keeps, per term, the two 128-bit halves, their signs and the
//! endomorphism image of the base (`32 + 1 + 64` bytes); each window recodes
//! its signed digits from the halves in closed form, so there is no digit
//! table. The terms are split in chunks whose split data takes at most half
//! the memory budget, and the chunk sums add up. Split data, window results
//! and concurrent bucket arrays are reserved against the same process-wide
//! 64 MiB scratch cap as the Pasta prover MSMs. If no allocation fits, a
//! stack-only complete scalar multiplication path preserves the result.

use ff::{Field, PrimeField};
use group::prime::PrimeCurveAffine;
use iroha_pasta::{
    CancellationToken, PastaAffine, PastaCurve, PastaField,
    msm::{
        BoundedSecretScalars, FixedBaseTable, MemoryBudget, MsmError, SharedMemoryBudget,
        msm_public_cancellable, msm_secret_bounded_cancellable, msm_secret_cancellable,
    },
    params::ParamsIpa,
};
use rayon::prelude::*;

// Scoped to the calling thread, before any commitment worker dispatch. This observes
// coefficient/evaluation commitments, including optional-table paths, without a
// process-wide test counter or any shipping configuration.
#[cfg(test)]
pub(crate) mod test_observation {
    use std::{cell::Cell, marker::PhantomData, rc::Rc, thread::LocalKey};

    thread_local! {
        static CALLS: Cell<Option<usize>> = const { Cell::new(None) };
    }

    /// An unwind-safe observation confined to its originating test thread.
    pub struct CommitmentProbe {
        calls: &'static LocalKey<Cell<Option<usize>>>,
        _not_send: PhantomData<Rc<()>>,
    }

    impl CommitmentProbe {
        /// Begin a non-nested observation of actual commitment entries.
        pub(crate) fn start() -> Self {
            CALLS.with(|calls| {
                assert!(calls.get().is_none(), "nested commitment probe");
                calls.set(Some(0));
            });
            Self {
                calls: &CALLS,
                _not_send: PhantomData,
            }
        }

        /// Number of calls through the shared commitment entry on this thread.
        pub(crate) fn calls(&self) -> usize {
            self.calls
                .with(|calls| calls.get().expect("active commitment probe"))
        }
    }

    impl Drop for CommitmentProbe {
        fn drop(&mut self) {
            self.calls.with(|calls| calls.set(None));
        }
    }

    pub(super) fn record() {
        CALLS.with(|calls| {
            if let Some(count) = calls.get() {
                calls.set(Some(
                    count.checked_add(1).expect("commitment probe overflow"),
                ));
            }
        });
    }
}

/// The key-generation blind (`Blind::default()` in the vendored code).
pub const DEFAULT_BLIND: u64 = 1;

/// Whether the committed scalars are secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Secrecy {
    /// Public scalars (fixed columns, instances, verifier data).
    Public,
    /// Witness-dependent scalars.
    Secret,
}

/// `sum_i scalars[i] * bases[i] + blind * w` with `scalars.len() <= bases.len()`.
#[allow(clippy::too_many_arguments)]
fn commit_with_bases<C: PastaCurve>(
    bases: &[C::AffineExt],
    table: Option<&FixedBaseTable<C>>,
    scalars: &[C::ScalarExt],
    blind: &C::ScalarExt,
    w: &C::AffineExt,
    secrecy: Secrecy,
    budget: MemoryBudget,
    cancellation: Option<&CancellationToken>,
) -> Result<C, MsmError> {
    #[cfg(test)]
    test_observation::record();
    CancellationToken::checkpoint(cancellation)?;
    let shared = SharedMemoryBudget::process_default();
    let bases = bases.get(..scalars.len()).ok_or(MsmError::LengthMismatch(
        iroha_pasta::LengthMismatch {
            left: scalars.len(),
            right: bases.len(),
        },
    ))?;
    let sum = match (table, secrecy) {
        (Some(table), Secrecy::Public) if table.len() == scalars.len() => {
            table.msm_public_cancellable(scalars, budget, &shared, cancellation)?
        }
        (Some(table), Secrecy::Secret) if table.len() == scalars.len() => {
            table.msm_secret_cancellable(scalars, budget, &shared, cancellation)?
        }
        (_, Secrecy::Public) => {
            msm_public_cancellable::<C>(scalars, bases, budget, &shared, cancellation)?
        }
        (_, Secrecy::Secret) => {
            msm_secret_cancellable::<C>(scalars, bases, budget, &shared, cancellation)?
        }
    };
    // The constant-time multiplication is stack-only; the variable-time
    // GLV helper allocates wNAF vectors outside MSM admission.
    let blind_term = w.to_curve() * *blind;
    CancellationToken::checkpoint(cancellation)?;
    Ok(sum + blind_term)
}

/// Commits to coefficients: `sum_i coeffs[i] g[i] + blind * W`.
///
/// # Errors
///
/// [`MsmError::LengthMismatch`] when `coeffs` is longer than `g`;
/// [`MsmError::Budget`] when the MSM does not fit `budget`.
pub fn commit<C: PastaCurve>(
    params: &ParamsIpa<C>,
    coeffs: &[C::ScalarExt],
    blind: &C::ScalarExt,
    secrecy: Secrecy,
    budget: MemoryBudget,
) -> Result<C, MsmError> {
    commit_cancellable(params, coeffs, blind, secrecy, budget, None)
}

/// Commits with a caller-owned cancellation signal, joining every task.
///
/// # Errors
/// As [`commit`], or [`MsmError::Cancelled`].
pub fn commit_cancellable<C: PastaCurve>(
    params: &ParamsIpa<C>,
    coeffs: &[C::ScalarExt],
    blind: &C::ScalarExt,
    secrecy: Secrecy,
    budget: MemoryBudget,
    cancellation: Option<&CancellationToken>,
) -> Result<C, MsmError> {
    commit_with_bases(
        params.g(),
        None,
        coeffs,
        blind,
        &params.w(),
        secrecy,
        budget,
        cancellation,
    )
}

/// Commits to evaluations: `sum_i values[i] g_lagrange[i] + blind * W`.
///
/// # Errors
///
/// As [`commit`].
pub fn commit_lagrange<C: PastaCurve>(
    params: &ParamsIpa<C>,
    values: &[C::ScalarExt],
    blind: &C::ScalarExt,
    secrecy: Secrecy,
    budget: MemoryBudget,
) -> Result<C, MsmError> {
    commit_lagrange_cancellable(params, values, blind, secrecy, budget, None)
}

/// Commits with a caller-owned cancellation signal, joining every task.
///
/// # Errors
/// As [`commit_lagrange`], or [`MsmError::Cancelled`].
pub fn commit_lagrange_cancellable<C: PastaCurve>(
    params: &ParamsIpa<C>,
    values: &[C::ScalarExt],
    blind: &C::ScalarExt,
    secrecy: Secrecy,
    budget: MemoryBudget,
    cancellation: Option<&CancellationToken>,
) -> Result<C, MsmError> {
    commit_with_bases(
        params.g_lagrange(),
        None,
        values,
        blind,
        &params.w(),
        secrecy,
        budget,
        cancellation,
    )
}

/// Commitment-key tables (precomputed window multiples of `g` and
/// `g_lagrange`) that a proving key may own. Results equal [`commit`] and
/// [`commit_lagrange`] bit for bit.
#[derive(Clone, Debug)]
pub struct CommitmentTables<C: PastaCurve> {
    g: Option<FixedBaseTable<C>>,
    g_lagrange: Option<FixedBaseTable<C>>,
}

impl<C: PastaCurve> Default for CommitmentTables<C> {
    fn default() -> Self {
        Self::none()
    }
}

impl<C: PastaCurve> CommitmentTables<C> {
    /// No tables: every commitment uses the variable-base MSM.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            g: None,
            g_lagrange: None,
        }
    }

    /// Builds the tables that fit `budget` (`g_lagrange` first, then `g`,
    /// each charged the whole budget separately); a table that does not fit
    /// is simply absent.
    #[must_use]
    pub fn build(params: &ParamsIpa<C>, budget: MemoryBudget) -> Self {
        Self {
            g_lagrange: FixedBaseTable::new(params.g_lagrange(), budget).ok(),
            g: FixedBaseTable::new(params.g(), budget).ok(),
        }
    }

    /// Build optional public tables while preserving typed cancellation.
    ///
    /// # Errors
    /// [`MsmError::Cancelled`] after construction tasks join. Budget refusal keeps the
    /// corresponding table absent, exactly as [`Self::build`].
    pub fn build_cancellable(
        params: &ParamsIpa<C>,
        budget: MemoryBudget,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<Self, MsmError> {
        let table = |bases| match FixedBaseTable::new_cancellable(bases, budget, cancellation) {
            Ok(table) => Ok(Some(table)),
            Err(MsmError::Budget(_)) => Ok(None),
            Err(error) => Err(error),
        };
        let g_lagrange = table(params.g_lagrange())?;
        let g = table(params.g())?;
        iroha_pasta::CancellationToken::checkpoint(cancellation)?;
        Ok(Self { g, g_lagrange })
    }

    /// Whether the `g` and `g_lagrange` tables exist.
    #[must_use]
    pub fn present(&self) -> (bool, bool) {
        (self.g.is_some(), self.g_lagrange.is_some())
    }

    /// [`commit`] through the `g` table when it covers `coeffs`.
    ///
    /// # Errors
    ///
    /// As [`commit`].
    pub fn commit(
        &self,
        params: &ParamsIpa<C>,
        coeffs: &[C::ScalarExt],
        blind: &C::ScalarExt,
        secrecy: Secrecy,
        budget: MemoryBudget,
    ) -> Result<C, MsmError> {
        self.commit_cancellable(params, coeffs, blind, secrecy, budget, None)
    }

    /// Commits with a caller-owned cancellation signal, joining every task.
    ///
    /// # Errors
    /// As [`Self::commit`], or [`MsmError::Cancelled`].
    pub fn commit_cancellable(
        &self,
        params: &ParamsIpa<C>,
        coeffs: &[C::ScalarExt],
        blind: &C::ScalarExt,
        secrecy: Secrecy,
        budget: MemoryBudget,
        cancellation: Option<&CancellationToken>,
    ) -> Result<C, MsmError> {
        commit_with_bases(
            params.g(),
            self.g.as_ref(),
            coeffs,
            blind,
            &params.w(),
            secrecy,
            budget,
            cancellation,
        )
    }

    /// [`commit_lagrange`] through the `g_lagrange` table when it covers
    /// `values`.
    ///
    /// # Errors
    ///
    /// As [`commit`].
    pub fn commit_lagrange(
        &self,
        params: &ParamsIpa<C>,
        values: &[C::ScalarExt],
        blind: &C::ScalarExt,
        secrecy: Secrecy,
        budget: MemoryBudget,
    ) -> Result<C, MsmError> {
        self.commit_lagrange_cancellable(params, values, blind, secrecy, budget, None)
    }

    /// Commit a secret evaluation column whose usable prefix has a public bound.
    /// The bound is `(prefix_len, bits)`; random padding stays full-width and the
    /// existing constant-time blind multiplication is unchanged. Optional tables
    /// keep their existing whole-column path, but only after prefix validation.
    pub(crate) fn commit_lagrange_bounded_prefix_cancellable(
        &self,
        params: &ParamsIpa<C>,
        values: &[C::ScalarExt],
        public_bound: (usize, usize),
        blind: &C::ScalarExt,
        budget: MemoryBudget,
        cancellation: Option<&CancellationToken>,
    ) -> Result<C, MsmError> {
        let (prefix_len, bits) = public_bound;
        let prefix = values.get(..prefix_len).ok_or(MsmError::LengthMismatch(
            iroha_pasta::LengthMismatch {
                left: prefix_len,
                right: values.len(),
            },
        ))?;
        let checked = BoundedSecretScalars::new(prefix, bits, cancellation)?;
        if self.g_lagrange.is_some() {
            return self.commit_lagrange_cancellable(
                params,
                values,
                blind,
                Secrecy::Secret,
                budget,
                cancellation,
            );
        }
        #[cfg(test)]
        test_observation::record();
        let all_bases = params.g_lagrange();
        let bases = all_bases
            .get(..values.len())
            .ok_or(MsmError::LengthMismatch(iroha_pasta::LengthMismatch {
                left: values.len(),
                right: all_bases.len(),
            }))?;
        let shared = SharedMemoryBudget::process_default();
        let mut sum = zeroize::Zeroizing::new(msm_secret_bounded_cancellable::<C>(
            &checked,
            &bases[..prefix_len],
            budget,
            &shared,
            cancellation,
        )?);
        // The first kernel has released its scratch before the padding kernel.
        *sum += msm_secret_cancellable::<C>(
            &values[prefix_len..],
            &bases[prefix_len..],
            budget,
            &shared,
            cancellation,
        )?;
        *sum += params.w().to_curve() * *blind;
        CancellationToken::checkpoint(cancellation)?;
        Ok(*sum)
    }

    /// Commits with a caller-owned cancellation signal, joining every task.
    ///
    /// # Errors
    /// As [`Self::commit_lagrange`], or [`MsmError::Cancelled`].
    pub fn commit_lagrange_cancellable(
        &self,
        params: &ParamsIpa<C>,
        values: &[C::ScalarExt],
        blind: &C::ScalarExt,
        secrecy: Secrecy,
        budget: MemoryBudget,
        cancellation: Option<&CancellationToken>,
    ) -> Result<C, MsmError> {
        commit_with_bases(
            params.g_lagrange(),
            self.g_lagrange.as_ref(),
            values,
            blind,
            &params.w(),
            secrecy,
            budget,
            cancellation,
        )
    }
}

/// Bytes of one projective bucket (three 32-byte coordinates).
const BUCKET_BYTES: usize = 96;
/// The widest window of [`msm_complete`].
const MAX_WINDOW: usize = 16;

/// The window width of [`msm_complete`] for `n` points: about `ln n`
/// (halo2's choice), narrowed until one window's buckets fit `budget`.
fn complete_window(n: usize, budget: MemoryBudget) -> usize {
    let mut window = if n < 4 {
        1
    } else if n < 32 {
        3
    } else {
        // ceil(log2(n) * ln 2), with ln 2 ~ 0.693.
        let log2 = usize::try_from(n.ilog2()).unwrap_or(usize::MAX);
        log2.saturating_mul(693).saturating_add(999) / 1000
    };
    window = window.clamp(1, MAX_WINDOW);
    while window > 1 && (BUCKET_BYTES << window) > budget.bytes() {
        window -= 1;
    }
    window
}

/// Bits `[start, start + width)` of a little-endian 256-bit integer.
fn window_digit(limbs: &[u64; 4], start: usize, width: usize) -> usize {
    let limb = start / 64;
    let offset = start % 64;
    let Some(low) = limbs.get(limb) else {
        return 0;
    };
    let mut value = low >> offset;
    if offset != 0
        && offset + width > 64
        && let Some(high) = limbs.get(limb + 1)
    {
        value |= high << (64 - offset);
    }
    // width <= MAX_WINDOW < 64, so the mask and the cast are exact.
    usize::try_from(value & ((1_u64 << width) - 1)).unwrap_or(0)
}

/// The sum of one window: buckets by digit, then the running-sum reduction.
fn complete_window_sum<C: PastaCurve>(
    limbs: &[[u64; 4]],
    bases: &[C::AffineExt],
    start: usize,
    width: usize,
    cancellation: Option<&CancellationToken>,
) -> C {
    let mut buckets = vec![C::identity(); (1_usize << width) - 1];
    for (index, (scalar, base)) in limbs.iter().zip(bases).enumerate() {
        if index % 256 == 0 && CancellationToken::checkpoint(cancellation).is_err() {
            return C::identity();
        }
        let digit = window_digit(scalar, start, width);
        if let Some(bucket) = digit
            .checked_sub(1)
            .and_then(|index| buckets.get_mut(index))
        {
            // Complete mixed addition: correct for equal, opposite and
            // identity inputs.
            *bucket += base;
        }
    }
    let mut running = C::identity();
    let mut sum = C::identity();
    for bucket in buckets.iter().rev() {
        running += bucket;
        sum += &running;
    }
    sum
}

/// The most bits of a GLV half (`|k1|, |k2| < 2^128`).
const GLV_HALF_BITS: usize = 128;
/// The widest signed window of the GLV path (`2^15` buckets).
const MAX_SIGNED_WINDOW: usize = 16;

/// The signed windows of a [`GLV_HALF_BITS`]-bit magnitude at width `width`:
/// one more than `ceil(128 / width)` takes the last carry.
const fn signed_windows(width: usize) -> usize {
    GLV_HALF_BITS.div_ceil(width) + 1
}

/// The signed window width of the GLV path for `terms` split terms: the
/// minimum of a cost model counting field multiplications (11 per complete
/// mixed addition into a bucket, 12 per complete addition of the running
/// sums, 8 per doubling), narrowed until one window's `2^(width - 1)`
/// buckets fit `budget`.
fn signed_window(terms: usize, budget: MemoryBudget) -> usize {
    let terms = u128::try_from(terms).unwrap_or(u128::MAX);
    let cost = |width: usize| -> u128 {
        let windows = u128::try_from(signed_windows(width)).unwrap_or(u128::MAX);
        let buckets = 1_u128 << (width - 1);
        let per_window = terms
            .saturating_mul(11)
            .saturating_add(buckets.saturating_mul(24))
            .saturating_add(u128::try_from(width).unwrap_or(0).saturating_mul(8));
        windows.saturating_mul(per_window)
    };
    let mut width = (1..=MAX_SIGNED_WINDOW)
        .min_by_key(|width| (cost(*width), *width))
        .unwrap_or(1);
    while width > 1 && (BUCKET_BYTES << (width - 1)) > budget.bytes() {
        width -= 1;
    }
    width
}

/// The signed digits of one window, for any magnitude `value < 2^128`.
///
/// Digit `w` of the sequential recoding (carry propagated from the least
/// significant window; digits in `(-2^(c - 1), 2^(c - 1)]`; the tests keep
/// it as the reference) depends on the lower
/// windows only through its incoming carry, and that carry has a closed
/// form: the lower `w` digits reach every residue modulo `2^(c w)` exactly
/// once between `-T_w + R_w` and `T_w`, where
/// `T_w = 2^(c - 1) (2^(c w) - 1) / (2^c - 1)` is their largest value and
/// `R_w = (2^(c w) - 1) / (2^c - 1)`. So the carry into window `w` is set
/// exactly when `value mod 2^(c w) > T_w`, and each window recodes its digit
/// from the magnitude alone. (For `c w > 128`, `T_w >= 2^(c w - 1) >= 2^128`
/// and no carry arrives.)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SignedWindow {
    /// `c w`.
    shift: usize,
    /// `c`.
    width: usize,
    /// `2^(c w) - 1`, the mask of the lower windows.
    low_mask: u128,
    /// `T_w`, or `None` when no carry can arrive (`w = 0`, or `c w > 128`).
    threshold: Option<u128>,
}

impl SignedWindow {
    /// Window `window` of width `width` (`1..=MAX_SIGNED_WINDOW`).
    fn new(width: usize, window: usize) -> Self {
        let shift = width.saturating_mul(window);
        let low_mask = match shift {
            0 => 0,
            1..GLV_HALF_BITS => (1_u128 << shift) - 1,
            _ => u128::MAX,
        };
        let threshold = (window > 0 && shift <= GLV_HALF_BITS)
            .then(|| {
                let radix_minus_one = (1_u128 << width) - 1;
                (low_mask / radix_minus_one).checked_mul(1_u128 << (width - 1))
            })
            .flatten();
        Self {
            shift,
            width,
            low_mask,
            threshold,
        }
    }

    /// The signed digit of this window of `value`.
    fn digit(self, value: u128) -> i32 {
        let full = 1_i32 << self.width;
        let half = 1_i32 << (self.width - 1);
        let bits = if self.shift < GLV_HALF_BITS {
            i32::try_from((value >> self.shift) & ((1_u128 << self.width) - 1)).unwrap_or(0)
        } else {
            0
        };
        let carry = i32::from(
            self.threshold
                .is_some_and(|threshold| value & self.low_mask > threshold),
        );
        let signed = bits + carry;
        if signed > half { signed - full } else { signed }
    }
}

/// The GLV split of a chunk of terms: per term the magnitudes `[k1, k2]` of
/// the halves, their signs (bit 0: `k1 < 0`, bit 1: `k2 < 0`) and the
/// endomorphism image `phi(B)` of the base. Digits are recoded per window
/// ([`SignedWindow`]), so no digit table is kept.
struct GlvTerms<A> {
    halves: Vec<[u128; 2]>,
    signs: Vec<u8>,
    images: Vec<A>,
}

/// Bytes of the split data of one term ([`GlvTerms`]).
fn glv_term_bytes<C: PastaCurve>() -> usize {
    core::mem::size_of::<[u128; 2]>()
        .saturating_add(1)
        .saturating_add(core::mem::size_of::<C::AffineExt>())
}

/// The terms of one GLV chunk under `budget`: its split data takes at most
/// half the budget (the buckets of a wave take the rest); at least one.
fn glv_chunk_terms<C: PastaCurve>(budget: MemoryBudget) -> usize {
    (budget.bytes() / 2 / glv_term_bytes::<C>()).max(1)
}

/// The GLV split of every term, or `None` when a split or an endomorphism
/// image is unavailable.
fn glv_terms<C: PastaCurve>(
    scalars: &[C::ScalarExt],
    bases: &[C::AffineExt],
    cancellation: Option<&CancellationToken>,
) -> Option<GlvTerms<C::AffineExt>> {
    let beta = <C::AffineExt as PastaAffine>::endo_beta();
    let terms = scalars.len().min(bases.len());
    let mut split = GlvTerms {
        halves: vec![[0_u128; 2]; terms],
        signs: vec![0_u8; terms],
        images: vec![C::AffineExt::identity(); terms],
    };
    split
        .halves
        .par_iter_mut()
        .zip(split.signs.par_iter_mut())
        .zip(split.images.par_iter_mut())
        .zip(scalars.par_iter().zip(bases))
        .try_for_each(|(((halves, signs), image), (scalar, base))| {
            if CancellationToken::checkpoint(cancellation).is_err() {
                return None;
            }
            let decomposition = C::glv_decompose(scalar)?;
            // phi(x, y) = (beta x, y) = [ZETA] (x, y); the identity (0, 0)
            // maps to itself.
            *image = Option::from(C::AffineExt::from_xy(base.x() * beta, base.y()))?;
            *halves = [decomposition.k1, decomposition.k2];
            *signs = u8::from(decomposition.k1_neg) | (u8::from(decomposition.k2_neg) << 1);
            Some(())
        })?;
    Some(split)
}

/// The sum of one signed window: `2^(width - 1)` buckets by digit magnitude
/// (the negated base for a negative signed half), then the running-sum
/// reduction. Each term adds its base for `k1` and its image for `k2`.
fn signed_window_sum<C: PastaCurve>(
    terms: &GlvTerms<C::AffineExt>,
    bases: &[C::AffineExt],
    window: usize,
    width: usize,
    cancellation: Option<&CancellationToken>,
) -> C {
    let recoder = SignedWindow::new(width, window);
    let mut buckets = vec![C::identity(); 1_usize << (width - 1)];
    let split = terms
        .halves
        .iter()
        .zip(&terms.signs)
        .zip(&terms.images)
        .zip(bases);
    for (index, (((halves, signs), image), base)) in split.enumerate() {
        if index % 256 == 0 && CancellationToken::checkpoint(cancellation).is_err() {
            return C::identity();
        }
        for (half, point, negative) in [
            (halves[0], base, signs & 1 != 0),
            (halves[1], image, signs & 2 != 0),
        ] {
            let digit = recoder.digit(half);
            let Some(bucket) = usize::try_from(digit.unsigned_abs())
                .ok()
                .and_then(|magnitude| magnitude.checked_sub(1))
                .and_then(|index| buckets.get_mut(index))
            else {
                continue;
            };
            // Complete mixed addition of the (possibly negated) affine
            // point: correct for equal, opposite and identity inputs.
            if (digit < 0) == negative {
                *bucket += point;
            } else {
                *bucket += &(-*point);
            }
        }
    }
    let mut running = C::identity();
    let mut sum = C::identity();
    for bucket in buckets.iter().rev() {
        running += bucket;
        sum += &running;
    }
    sum
}

/// Runs `window_sum` for every window in waves of at most `concurrency`
/// windows and combines them from the top: `sum_w 2^(width w) S_w` with
/// complete doublings and additions.
fn combine_windows<C: PastaCurve>(
    windows: usize,
    width: usize,
    concurrency: usize,
    window_sum: impl Fn(usize) -> C + Sync,
    cancellation: Option<&CancellationToken>,
) -> C {
    let concurrency = concurrency.clamp(1, windows.max(1));
    let mut sums = vec![C::identity(); windows];
    for (wave, slots) in sums.chunks_mut(concurrency).enumerate() {
        if CancellationToken::checkpoint(cancellation).is_err() {
            return C::identity();
        }
        slots.par_iter_mut().enumerate().for_each(|(slot, sum)| {
            if CancellationToken::checkpoint(cancellation).is_err() {
                return;
            }
            *sum = window_sum(wave * concurrency + slot);
        });
    }
    let mut total = C::identity();
    for sum in sums.iter().rev() {
        for _ in 0..width {
            total = total.double();
        }
        total += sum;
    }
    total
}

/// Accounts for persistent columns, all window results, and every bucket
/// array in one parallel wave before any of those allocations are made.
fn window_scratch<C: PastaCurve>(
    persistent: usize,
    windows: usize,
    buckets_per_window: usize,
    budget: MemoryBudget,
) -> Option<(usize, usize)> {
    let point = core::mem::size_of::<C>();
    let fixed = persistent.checked_add(windows.checked_mul(point)?)?;
    let window = buckets_per_window.checked_mul(point)?;
    let concurrency = budget
        .bytes()
        .checked_sub(fixed)?
        .checked_div(window)?
        .min(windows)
        .min(rayon::current_num_threads());
    if concurrency == 0 {
        return None;
    }
    Some((
        concurrency,
        fixed.checked_add(concurrency.checked_mul(window)?)?,
    ))
}

/// Complete scalar multiplication uses a stack-only fixed window. Scarce scratch
/// changes performance, never the verifier's accepted group equation.
fn complete_without_scratch<C: PastaCurve>(
    scalars: &[C::ScalarExt],
    bases: &[C::AffineExt],
    cancellation: Option<&CancellationToken>,
) -> C {
    let mut sum = C::identity();
    for (scalar, base) in scalars.iter().zip(bases) {
        if CancellationToken::checkpoint(cancellation).is_err() {
            return C::identity();
        }
        sum += base.to_curve() * *scalar;
    }
    sum
}

/// [`msm_complete`] on GLV-split, signed-digit windows, or `None` when a
/// split is unavailable. The terms are split in chunks of
/// [`glv_chunk_terms`] whose sums add up: the split data never takes more
/// than half the budget.
fn msm_complete_glv<C: PastaCurve>(
    scalars: &[C::ScalarExt],
    bases: &[C::AffineExt],
    budget: MemoryBudget,
    shared: &SharedMemoryBudget,
    cancellation: Option<&CancellationToken>,
) -> Option<C> {
    let n = scalars.len().min(bases.len());
    let mut total = C::identity();
    let mut start = 0;
    while start < n {
        if CancellationToken::checkpoint(cancellation).is_err() {
            return Some(C::identity());
        }
        let available = MemoryBudget::new(budget.bytes().min(shared.available_bytes()));
        let count = glv_chunk_terms::<C>(available).min(n - start);
        let split_bytes = count.saturating_mul(glv_term_bytes::<C>());
        let buckets = MemoryBudget::new(available.bytes().saturating_sub(split_bytes));
        let preferred = signed_window(count.saturating_mul(2), buckets);
        let plan = (1..=preferred).rev().find_map(|width| {
            let windows = signed_windows(width);
            window_scratch::<C>(split_bytes, windows, 1 << (width - 1), available)
                .map(|(concurrency, bytes)| (width, windows, concurrency, bytes))
        });
        let Some((width, windows, concurrency, bytes)) = plan else {
            return Some(
                total
                    + complete_without_scratch::<C>(
                        &scalars[start..n],
                        &bases[start..n],
                        cancellation,
                    ),
            );
        };
        // Never wait while a Rayon task may own another reservation.
        let Some(_scratch) = shared.try_reserve(bytes) else {
            return Some(
                total
                    + complete_without_scratch::<C>(
                        &scalars[start..n],
                        &bases[start..n],
                        cancellation,
                    ),
            );
        };
        let end = start + count;
        let terms = glv_terms::<C>(&scalars[start..end], &bases[start..end], cancellation)?;
        total += combine_windows(
            windows,
            width,
            concurrency,
            |window| {
                signed_window_sum::<C>(&terms, &bases[start..end], window, width, cancellation)
            },
            cancellation,
        );
        start = end;
    }
    Some(total)
}

/// `sum_i scalars[i] * bases[i]` for public data with complete formulas only
/// (see the module documentation, S10). The scalars and bases must have
/// equal lengths; extra entries of the longer one are ignored. Each scalar is
/// split with the GLV endomorphism into two signed-digit halves (see the
/// module documentation). Windows run in waves on the caller's Rayon pool,
/// limited by both `budget` and the process-wide shared MSM scratch cap.
/// Windows are combined in order, so the result is the same group element
/// for every thread count and budget. With no scratch available it uses
/// complete scalar multiplications without heap allocation. It never fails.
#[must_use]
pub fn msm_complete<C: PastaCurve>(
    scalars: &[C::ScalarExt],
    bases: &[C::AffineExt],
    budget: MemoryBudget,
) -> C {
    msm_complete_with_shared_budget(
        scalars,
        bases,
        budget,
        &SharedMemoryBudget::process_default(),
    )
}

/// [`msm_complete`] with an additional shared caller scratch ceiling.
///
/// All kernel-owned heap buffers, including GLV splits, scalar limbs,
/// window results and concurrent bucket arrays, are admitted before
/// allocation. Contention uses the allocation-free complete path without
/// waiting, and cannot change the result. Input slices and retained caller
/// data are outside this scratch budget.
#[must_use]
pub fn msm_complete_with_shared_budget<C: PastaCurve>(
    scalars: &[C::ScalarExt],
    bases: &[C::AffineExt],
    budget: MemoryBudget,
    shared: &SharedMemoryBudget,
) -> C {
    msm_complete_cancellable(scalars, bases, budget, shared, None).expect("no cancellation signal")
}

/// Complete-formula public MSM with explicit cooperative cancellation.
///
/// # Errors
/// Returns cancellation only after all Rayon tasks join and scratch permits
/// release; no partial group equation is exposed to verifier callers.
pub fn msm_complete_cancellable<C: PastaCurve>(
    scalars: &[C::ScalarExt],
    bases: &[C::AffineExt],
    budget: MemoryBudget,
    shared: &SharedMemoryBudget,
    cancellation: Option<&CancellationToken>,
) -> Result<C, iroha_pasta::Cancelled> {
    CancellationToken::checkpoint(cancellation)?;
    debug_assert_eq!(scalars.len(), bases.len());
    let n = scalars.len().min(bases.len());
    if n == 0 {
        return Ok(C::identity());
    }
    let (scalars, bases) = (&scalars[..n], &bases[..n]);
    let candidate = msm_complete_glv::<C>(scalars, bases, budget, shared, cancellation);
    CancellationToken::checkpoint(cancellation)?;
    let result = candidate.unwrap_or_else(|| {
        msm_complete_unsigned::<C>(scalars, bases, budget, shared, cancellation)
    });
    CancellationToken::checkpoint(cancellation)?;
    Ok(result)
}

/// [`msm_complete`] on unsigned full-width windows: the fallback when a GLV
/// split is unavailable, and the differential reference of the tests.
fn msm_complete_unsigned<C: PastaCurve>(
    scalars: &[C::ScalarExt],
    bases: &[C::AffineExt],
    budget: MemoryBudget,
    shared: &SharedMemoryBudget,
    cancellation: Option<&CancellationToken>,
) -> C {
    let n = scalars.len().min(bases.len());
    if n == 0 {
        return C::identity();
    }
    let available = MemoryBudget::new(budget.bytes().min(shared.available_bytes()));
    let persistent = n.saturating_mul(core::mem::size_of::<[u64; 4]>());
    let buckets = MemoryBudget::new(available.bytes().saturating_sub(persistent));
    let preferred = complete_window(n, buckets);
    let bits = usize::try_from(<C::ScalarExt as PrimeField>::NUM_BITS).unwrap_or(256);
    let plan = (1..=preferred).rev().find_map(|width| {
        let windows = bits.div_ceil(width);
        window_scratch::<C>(persistent, windows, (1 << width) - 1, available)
            .map(|(concurrency, bytes)| (width, windows, concurrency, bytes))
    });
    let Some((width, windows, concurrency, bytes)) = plan else {
        return complete_without_scratch::<C>(scalars, bases, cancellation);
    };
    let Some(_scratch) = shared.try_reserve(bytes) else {
        return complete_without_scratch::<C>(scalars, bases, cancellation);
    };
    let limbs: Vec<[u64; 4]> = scalars[..n]
        .par_iter()
        .map(|scalar| {
            let repr = scalar.to_repr();
            let mut limbs = [0_u64; 4];
            for (limb, chunk) in limbs.iter_mut().zip(repr.as_ref().chunks_exact(8)) {
                let mut word = [0_u8; 8];
                word.copy_from_slice(chunk);
                *limb = u64::from_le_bytes(word);
            }
            limbs
        })
        .collect();
    let bases = &bases[..n];
    combine_windows(
        windows,
        width,
        concurrency,
        |window| complete_window_sum::<C>(&limbs, bases, window * width, width, cancellation),
        cancellation,
    )
}

/// A linear combination of points `sum_i scalars[i] * bases[i]` (public
/// data): the commitment a verifier opens, or the left-hand side it checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Msm<C: PastaCurve> {
    scalars: Vec<C::ScalarExt>,
    bases: Vec<C::AffineExt>,
}

impl<C: PastaCurve> Default for Msm<C> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: PastaCurve> Msm<C> {
    /// The empty combination (the identity).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            scalars: Vec::new(),
            bases: Vec::new(),
        }
    }

    /// The single point `point`.
    #[must_use]
    pub fn from_point(point: C::AffineExt) -> Self {
        Self {
            scalars: vec![C::ScalarExt::ONE],
            bases: vec![point],
        }
    }

    /// Adds `scalar * point`.
    pub fn push(&mut self, scalar: C::ScalarExt, point: C::AffineExt) {
        self.scalars.push(scalar);
        self.bases.push(point);
    }

    /// Multiplies every term by `factor`.
    pub fn scale(&mut self, factor: &C::ScalarExt) {
        for scalar in &mut self.scalars {
            *scalar *= factor;
        }
    }

    /// Adds every term of `other`.
    pub fn add_msm(&mut self, other: &Self) {
        self.scalars.extend_from_slice(&other.scalars);
        self.bases.extend_from_slice(&other.bases);
    }

    /// The number of terms.
    #[must_use]
    pub fn len(&self) -> usize {
        self.scalars.len()
    }

    /// Whether there are no terms.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.scalars.is_empty()
    }

    /// The terms as `(scalar, base)` pairs.
    pub fn terms(&self) -> impl Iterator<Item = (&C::ScalarExt, &C::AffineExt)> {
        self.scalars.iter().zip(self.bases.iter())
    }

    /// Evaluates the combination with [`msm_complete`] (complete formulas
    /// only; never fails for lack of memory).
    #[must_use]
    pub fn evaluate(&self, budget: MemoryBudget) -> C {
        msm_complete::<C>(&self.scalars, &self.bases, budget)
    }

    /// Evaluate with an explicit signal, preserving complete group operations.
    /// # Errors
    /// Cancellation after all admitted kernel tasks join and scratch is released.
    pub fn evaluate_cancellable(
        &self,
        budget: MemoryBudget,
        cancellation: Option<&CancellationToken>,
    ) -> Result<C, iroha_pasta::Cancelled> {
        msm_complete_cancellable::<C>(
            &self.scalars,
            &self.bases,
            budget,
            &SharedMemoryBudget::process_default(),
            cancellation,
        )
    }

    /// Whether the combination is the identity.
    #[must_use]
    pub fn is_identity(&self, budget: MemoryBudget) -> bool {
        bool::from(self.evaluate(budget).is_identity())
    }

    /// The evaluated combination in affine form.
    #[must_use]
    pub fn to_affine(&self, budget: MemoryBudget) -> C::AffineExt {
        self.evaluate(budget).to_affine()
    }
}

/// The key-generation blind as a field element.
pub(crate) fn default_blind<F: PastaField>() -> F {
    F::from(DEFAULT_BLIND)
}

#[cfg(test)]
mod tests {
    use group::{Curve, Group};
    use iroha_pasta::msm::msm_public;
    use iroha_pasta::{Ep, Eq, Fq, msm::msm_naive};
    use rand_chacha::ChaCha20Rng;
    use rand_core_06::SeedableRng;

    use super::*;

    /// Adversarial MSM inputs of `n` terms: random, repeated, opposite and
    /// identity bases; zero, one, minus one, small, all-ones-window and
    /// random scalars; terms that cancel to the identity.
    fn adversarial<C: PastaCurve>(
        n: usize,
        rng: &mut ChaCha20Rng,
    ) -> (Vec<C::ScalarExt>, Vec<C::AffineExt>) {
        let base = C::random(&mut *rng).to_affine();
        let scalars = (0..n)
            .map(|i| match i % 7 {
                0 => C::ScalarExt::ZERO,
                1 => C::ScalarExt::ONE,
                2 => -C::ScalarExt::ONE,
                3 => C::ScalarExt::from(u64::MAX),
                4 => C::ScalarExt::from(0xffff),
                _ => C::ScalarExt::random(&mut *rng),
            })
            .collect();
        let bases = (0..n)
            .map(|i| match i % 5 {
                0 => base,
                1 => -base,
                2 => C::AffineExt::identity(),
                _ => C::random(&mut *rng).to_affine(),
            })
            .collect();
        (scalars, bases)
    }

    fn complete_matches_naive<C: PastaCurve>(seed: u64) {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        for n in [0_usize, 1, 2, 3, 4, 5, 8, 31, 32, 33, 100, 257] {
            let (scalars, bases) = adversarial::<C>(n, &mut rng);
            let expected = msm_naive::<C>(&scalars, &bases);
            for budget in [
                MemoryBudget::DEFAULT,
                MemoryBudget::new(0),
                MemoryBudget::new(BUCKET_BYTES * 8),
            ] {
                assert_eq!(
                    msm_complete::<C>(&scalars, &bases, budget),
                    expected,
                    "n = {n}, budget = {budget:?}"
                );
            }
            for threads in [1, 2, 4, 7] {
                let pool = rayon::ThreadPoolBuilder::new()
                    .num_threads(threads)
                    .build()
                    .expect("pool");
                let pooled =
                    pool.install(|| msm_complete::<C>(&scalars, &bases, MemoryBudget::DEFAULT));
                assert_eq!(pooled, expected, "n = {n}, {threads} threads");
            }
        }
        // Terms that cancel: P + (-1) P, 2P - P - P, equal bases summed.
        let p = C::random(&mut rng).to_affine();
        let one = C::ScalarExt::ONE;
        let cancel = msm_complete::<C>(
            &[one, -one, one + one, -one, -one],
            &[p, p, p, p, p],
            MemoryBudget::DEFAULT,
        );
        assert!(bool::from(cancel.is_identity()));
        let doubled = msm_complete::<C>(&[one, one], &[p, p], MemoryBudget::DEFAULT);
        assert_eq!(doubled, p.to_curve().double());
    }

    #[test]
    fn complete_msm_matches_the_naive_msm_on_adversarial_inputs() {
        complete_matches_naive::<Ep>(11);
        complete_matches_naive::<Eq>(12);
    }

    /// The sequential signed-digit recoding, the reference of
    /// [`SignedWindow`]: `out.len()` digits of `width <= 16` bits, least
    /// significant first, `value = sum_w out[w] 2^(width w)` with every digit
    /// in `(-2^(width - 1), 2^(width - 1)]`. Returns the carry left after the
    /// last digit (zero when `out` has [`signed_windows`] digits).
    fn signed_digits(value: u128, width: usize, out: &mut [i32]) -> i32 {
        let full = 1_i32 << width;
        let half = 1_i32 << (width - 1);
        let mask = (1_u128 << width) - 1;
        let mut carry = 0_i32;
        for (window, digit) in out.iter_mut().enumerate() {
            let shift = window.saturating_mul(width);
            let bits = if shift < GLV_HALF_BITS {
                i32::try_from((value >> shift) & mask).unwrap_or(0)
            } else {
                0
            };
            let mut signed = bits + carry;
            carry = 0;
            if signed > half {
                signed -= full;
                carry = 1;
            }
            *digit = signed;
        }
        carry
    }

    #[test]
    fn per_window_digits_equal_the_sequential_recoding() {
        let mut rng = ChaCha20Rng::seed_from_u64(29);
        let mut values = vec![
            0_u128,
            1,
            u128::MAX,
            u128::MAX - 1,
            1 << 127,
            (1 << 127) - 1,
            0x5555_5555_5555_5555_5555_5555_5555_5555,
            0xaaaa_aaaa_aaaa_aaaa_aaaa_aaaa_aaaa_aaaa,
            0x8000_0000_0000_0001_8000_0000_0000_0001,
        ];
        values.extend((0..200).map(|_| {
            let high = u128::from(rand_core_06::RngCore::next_u64(&mut rng));
            let low = u128::from(rand_core_06::RngCore::next_u64(&mut rng));
            (high << 64) | low
        }));
        // Runs of digits at the half boundary, where the carries chain.
        for width in 1..=MAX_SIGNED_WINDOW {
            let half = 1_u128 << (width - 1);
            let mut run = 0_u128;
            let mut shift = 0;
            while shift < GLV_HALF_BITS {
                run |= half << shift;
                values.push(run);
                values.push(run.wrapping_add(1));
                shift += width;
            }
        }
        for width in 1..=MAX_SIGNED_WINDOW {
            let windows = signed_windows(width);
            for value in &values {
                let mut digits = vec![0_i32; windows];
                assert_eq!(signed_digits(*value, width, &mut digits), 0);
                for (window, digit) in digits.iter().enumerate() {
                    assert_eq!(
                        SignedWindow::new(width, window).digit(*value),
                        *digit,
                        "width {width} window {window} value {value:#x}"
                    );
                }
            }
            // A window past the last one carries nothing.
            assert_eq!(SignedWindow::new(width, windows).digit(u128::MAX), 0);
        }
        assert_eq!(
            SignedWindow::new(16, 8).threshold.map(|t| t > 0),
            Some(true)
        );
        assert_eq!(SignedWindow::new(16, 9).threshold, None);
        assert_eq!(SignedWindow::new(4, 0).threshold, None);
    }

    #[test]
    fn glv_chunks_bound_the_split_data_by_the_budget() {
        let term = glv_term_bytes::<Ep>();
        assert_eq!(
            term,
            32 + 1 + core::mem::size_of::<<Ep as PastaCurve>::AffineExt>()
        );
        assert_eq!(glv_chunk_terms::<Ep>(MemoryBudget::new(0)), 1);
        assert_eq!(glv_chunk_terms::<Ep>(MemoryBudget::new(10 * term)), 5);
        assert!(glv_chunk_terms::<Eq>(MemoryBudget::DEFAULT) > 1 << 20);
        // Chunked sums equal one MSM.
        let mut rng = ChaCha20Rng::seed_from_u64(31);
        let n = 37;
        let scalars: Vec<Fq> = (0..n).map(|_| Fq::random(&mut rng)).collect();
        let bases: Vec<_> = (0..n).map(|_| Ep::random(&mut rng).to_affine()).collect();
        let expected = msm_naive::<Ep>(&scalars, &bases);
        for terms in [1, 2, 5, 36, 37, 64] {
            let budget = MemoryBudget::new(2 * terms * term);
            assert_eq!(glv_chunk_terms::<Ep>(budget), terms);
            assert_eq!(
                msm_complete_glv::<Ep>(
                    &scalars,
                    &bases,
                    budget,
                    &SharedMemoryBudget::process_default(),
                    None
                ),
                Some(expected),
                "{terms} terms per chunk"
            );
        }
    }

    /// One verifier MSM at the decide size `n = 2^16` on one thread, for
    /// the peak RSS (`/usr/bin/time -l`) of its working set.
    #[test]
    #[ignore = "working-set measurement; run in release under /usr/bin/time -l"]
    fn measure_complete_msm_working_set() {
        use std::time::Instant;

        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let n = 1_usize << 16;
        let bases: Vec<_> = (0..n).map(|_| Ep::random(&mut rng).to_affine()).collect();
        let scalars: Vec<Fq> = (0..n).map(|_| Fq::random(&mut rng)).collect();
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .expect("pool");
        let started = Instant::now();
        let result = pool.install(|| msm_complete::<Ep>(&scalars, &bases, MemoryBudget::DEFAULT));
        println!(
            "MSM_WORKING_SET n=2^16 inputs_bytes={} split_bytes={} elapsed={:?} identity={}",
            n * (core::mem::size_of::<Fq>()
                + core::mem::size_of::<<Ep as PastaCurve>::AffineExt>()),
            n * glv_term_bytes::<Ep>(),
            started.elapsed(),
            bool::from(result.is_identity()),
        );
    }

    #[test]
    fn signed_digits_reconstruct_their_magnitudes() {
        let values = [
            0_u128,
            1,
            2,
            u128::from(u64::MAX),
            1 << 127,
            (1 << 127) - 1,
            u128::MAX,
            u128::MAX - 1,
            0x5555_5555_5555_5555_5555_5555_5555_5555,
            0xaaaa_aaaa_aaaa_aaaa_aaaa_aaaa_aaaa_aaaa,
            0x8000_0000_0000_0001_8000_0000_0000_0001,
        ];
        for width in 1..=MAX_SIGNED_WINDOW {
            let windows = signed_windows(width);
            let half = 1_i64 << (width - 1);
            for value in values {
                let mut digits = vec![0_i32; windows];
                assert_eq!(signed_digits(value, width, &mut digits), 0, "{width}");
                // sum_w d_w 2^(width w) == value, digits in (-half, half].
                let mut total = Fq::ZERO;
                let radix = Fq::from(2_u64).pow_vartime([u64::try_from(width).expect("width")]);
                for digit in digits.iter().rev() {
                    assert!(i64::from(*digit) > -half && i64::from(*digit) <= half);
                    let magnitude = Fq::from(u64::from(digit.unsigned_abs()));
                    total = total * radix + if *digit < 0 { -magnitude } else { magnitude };
                }
                assert_eq!(
                    total,
                    Fq::from_u128(value),
                    "width {width} value {value:#x}"
                );
            }
            // Too few digits leave a carry (or drop high bits).
            let mut short = vec![0_i32; 1];
            if width < 128 {
                let carry = signed_digits(u128::MAX, width, &mut short);
                assert!(carry != 0 || short[0] != 0);
            }
        }
    }

    #[test]
    fn signed_windows_follow_the_cost_model_and_the_budget() {
        assert_eq!(signed_windows(10), 14);
        assert_eq!(signed_windows(16), 9);
        assert_eq!(signed_windows(1), 129);
        // About 2^12 split terms (k = 11) choose 9- to 10-bit windows.
        let width = signed_window(1 << 12, MemoryBudget::DEFAULT);
        assert!((9..=10).contains(&width), "{width}");
        assert!(signed_window(1 << 20, MemoryBudget::DEFAULT) > width);
        assert!(signed_window(2, MemoryBudget::DEFAULT) <= 4);
        assert_eq!(signed_window(1 << 20, MemoryBudget::new(0)), 1);
        assert_eq!(
            signed_window(1 << 20, MemoryBudget::new(BUCKET_BYTES << 4)),
            5
        );
    }

    /// The GLV path equals the unsigned path and the naive MSM on inputs
    /// built around the endomorphism: `B` with `[ZETA] B` and `-[ZETA] B` in
    /// one MSM, scalars `±ZETA`, `±ZETA^2`, halves at `2^127` and `2^128`.
    fn glv_matches_unsigned<C: PastaCurve>(seed: u64) {
        use ff::WithSmallOrderMulGroup;
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let zeta = <C::ScalarExt as WithSmallOrderMulGroup<3>>::ZETA;
        let p = C::random(&mut rng);
        let endo = p.endo();
        let two_127 = C::ScalarExt::from_u128(1 << 127);
        let two_128 = two_127.double();
        let special = [
            zeta,
            -zeta,
            zeta.square(),
            -zeta.square(),
            C::ScalarExt::ONE,
            -C::ScalarExt::ONE,
            two_127,
            two_128,
            two_128 - C::ScalarExt::ONE,
            -two_128,
            C::ScalarExt::ZERO,
            zeta + C::ScalarExt::ONE,
        ];
        let bases_cycle = [
            p.to_affine(),
            endo.to_affine(),
            (-endo).to_affine(),
            endo.endo().to_affine(),
            C::AffineExt::identity(),
        ];
        for n in [1_usize, 2, 5, 12, 60, 300] {
            let scalars: Vec<C::ScalarExt> = (0..n)
                .map(|i| {
                    if i % 3 == 2 {
                        C::ScalarExt::random(&mut rng)
                    } else {
                        special[i % special.len()]
                    }
                })
                .collect();
            let bases: Vec<C::AffineExt> =
                (0..n).map(|i| bases_cycle[i % bases_cycle.len()]).collect();
            let expected = msm_naive::<C>(&scalars, &bases);
            for budget in [
                MemoryBudget::DEFAULT,
                MemoryBudget::new(0),
                MemoryBudget::new(BUCKET_BYTES * 8),
            ] {
                assert_eq!(
                    msm_complete_glv::<C>(
                        &scalars,
                        &bases,
                        budget,
                        &SharedMemoryBudget::process_default(),
                        None
                    ),
                    Some(expected),
                    "n = {n}"
                );
                assert_eq!(
                    msm_complete_unsigned::<C>(
                        &scalars,
                        &bases,
                        budget,
                        &SharedMemoryBudget::process_default(),
                        None
                    ),
                    expected
                );
            }
        }
        // `zeta P - [ZETA] P` cancels inside the split.
        let cancel = msm_complete::<C>(
            &[zeta, -C::ScalarExt::ONE],
            &[p.to_affine(), endo.to_affine()],
            MemoryBudget::DEFAULT,
        );
        assert!(bool::from(cancel.is_identity()));
    }

    #[test]
    fn glv_path_matches_the_unsigned_path_around_the_endomorphism() {
        glv_matches_unsigned::<Ep>(21);
        glv_matches_unsigned::<Eq>(22);
    }

    #[test]
    #[ignore = "random differential sweep; run in release"]
    fn glv_path_matches_the_unsigned_path_on_random_inputs() {
        let mut rng = ChaCha20Rng::seed_from_u64(23);
        for round in 0..64 {
            let n = 1 + (round * 37) % 700;
            let scalars: Vec<Fq> = (0..n).map(|_| Fq::random(&mut rng)).collect();
            let bases: Vec<_> = (0..n).map(|_| Ep::random(&mut rng).to_affine()).collect();
            assert_eq!(
                msm_complete_glv::<Ep>(
                    &scalars,
                    &bases,
                    MemoryBudget::DEFAULT,
                    &SharedMemoryBudget::process_default(),
                    None
                ),
                Some(msm_complete_unsigned::<Ep>(
                    &scalars,
                    &bases,
                    MemoryBudget::DEFAULT,
                    &SharedMemoryBudget::process_default(),
                    None
                )),
                "round {round}"
            );
        }
    }

    #[test]
    fn window_scratch_accounts_for_all_heap_buffers() {
        let point = core::mem::size_of::<Ep>();
        let persistent = 17 * glv_term_bytes::<Ep>();
        let windows = signed_windows(4);
        let buckets = 1 << 3;
        let minimum = persistent + (windows + buckets) * point;
        assert!(
            window_scratch::<Ep>(persistent, windows, buckets, MemoryBudget::new(minimum - 1))
                .is_none()
        );
        assert_eq!(
            window_scratch::<Ep>(persistent, windows, buckets, MemoryBudget::new(minimum)),
            Some((1, minimum))
        );
        assert!(
            window_scratch::<Ep>(usize::MAX, windows, buckets, MemoryBudget::DEFAULT).is_none()
        );
        for workers in [1, 4] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(workers)
                .build()
                .expect("pool");
            let (concurrency, bytes) = pool.install(|| {
                window_scratch::<Ep>(persistent, windows, buckets, MemoryBudget::DEFAULT)
                    .expect("plan")
            });
            assert_eq!(concurrency, workers);
            assert_eq!(
                bytes,
                persistent + windows * point + workers * buckets * point
            );
        }
    }

    /// Concurrent complete verifier MSMs use shared admission, and a zero
    /// shared ceiling exercises the stack-only path on both kernels.
    fn complete_shared_budget<C: PastaCurve>(seed: u64) {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let (scalars, bases) = adversarial::<C>(65, &mut rng);
        let expected = msm_naive::<C>(&scalars, &bases);
        let shared = SharedMemoryBudget::new(32 << 10);
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(4)
            .build()
            .expect("pool");
        pool.install(|| {
            (0..8).into_par_iter().for_each(|_| {
                assert_eq!(
                    msm_complete_with_shared_budget::<C>(
                        &scalars,
                        &bases,
                        MemoryBudget::DEFAULT,
                        &shared
                    ),
                    expected
                );
            });
        });
        assert_eq!(shared.in_use_bytes(), 0);
        assert!(shared.peak_bytes() <= shared.limit_bytes());
        // A zero caller cap deterministically exercises fallback without
        // depending on unrelated process reservations made by other tests.
        let blocked = SharedMemoryBudget::new(0);
        pool.install(|| {
            assert_eq!(
                msm_complete_with_shared_budget::<C>(
                    &scalars,
                    &bases,
                    MemoryBudget::DEFAULT,
                    &blocked
                ),
                expected
            );
            assert_eq!(
                msm_complete_unsigned::<C>(&scalars, &bases, MemoryBudget::DEFAULT, &blocked, None),
                expected
            );
        });
        assert_eq!(blocked.peak_bytes(), 0);
        assert_eq!(blocked.in_use_bytes(), 0);
        let single = rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .expect("one-worker pool");
        let saturated = SharedMemoryBudget::new(1);
        let held = saturated.try_reserve(1).expect("one byte of scratch");
        // An admission wait here would deadlock: this worker cannot drop
        // its reservation until both nested calls return.
        let nested = || {
            msm_complete_with_shared_budget::<C>(
                &scalars,
                &bases,
                MemoryBudget::DEFAULT,
                &saturated,
            )
        };
        assert_eq!(
            single.install(|| rayon::join(nested, nested)),
            (expected, expected)
        );
        assert_eq!(saturated.in_use_bytes(), 1);
        drop(held);
        assert_eq!(saturated.in_use_bytes(), 0);
    }

    #[test]
    fn complete_msm_shared_cap_and_contention_preserve_both_curves() {
        complete_shared_budget::<Ep>(85);
        complete_shared_budget::<Eq>(86);
    }

    /// Release timing of the verifier MSM against the prover-only
    /// batch-affine `msm_public` (run with `--release -- --ignored
    /// --nocapture`).
    #[test]
    #[ignore = "timing measurement; run in release"]
    fn measure_complete_msm() {
        use std::time::Instant;

        let mut rng = ChaCha20Rng::seed_from_u64(1);
        for log in [10_u32, 12, 14, 16] {
            let n = 1_usize << log;
            let bases: Vec<_> = (0..n).map(|_| Ep::random(&mut rng).to_affine()).collect();
            let scalars: Vec<Fq> = (0..n).map(|_| Fq::random(&mut rng)).collect();
            for threads in [1, 4] {
                let pool = rayon::ThreadPoolBuilder::new()
                    .num_threads(threads)
                    .build()
                    .expect("pool");
                let started = Instant::now();
                let complete =
                    pool.install(|| msm_complete::<Ep>(&scalars, &bases, MemoryBudget::DEFAULT));
                let complete_time = started.elapsed();
                let started = Instant::now();
                let affine = pool
                    .install(|| msm_public::<Ep>(&scalars, &bases, MemoryBudget::DEFAULT))
                    .expect("msm");
                let affine_time = started.elapsed();
                assert_eq!(complete, affine);
                println!(
                    "n=2^{log} threads={threads}: complete {complete_time:?}, \
                     batch-affine {affine_time:?}"
                );
            }
        }
    }

    #[test]
    fn complete_msm_windows_and_digits() {
        assert_eq!(complete_window(1, MemoryBudget::DEFAULT), 1);
        assert_eq!(complete_window(10, MemoryBudget::DEFAULT), 3);
        assert_eq!(complete_window(1 << 16, MemoryBudget::DEFAULT), 12);
        assert_eq!(complete_window(1 << 30, MemoryBudget::DEFAULT), MAX_WINDOW);
        // The window narrows until one window's buckets fit the budget.
        assert_eq!(complete_window(1 << 16, MemoryBudget::new(0)), 1);
        assert_eq!(
            complete_window(1 << 16, MemoryBudget::new(BUCKET_BYTES << 5)),
            5
        );
        let limbs = [0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210, 1, u64::MAX];
        assert_eq!(window_digit(&limbs, 0, 8), 0xef);
        assert_eq!(window_digit(&limbs, 60, 8), 0x00);
        assert_eq!(window_digit(&limbs, 56, 12), 0x001);
        assert_eq!(window_digit(&limbs, 120, 12), 0x1fe);
        assert_eq!(window_digit(&limbs, 252, 8), 0x0f);
        assert_eq!(window_digit(&limbs, 256, 8), 0);
    }

    fn params() -> ParamsIpa<Ep> {
        ParamsIpa::new(4).expect("k = 4")
    }

    #[test]
    fn commitments_agree_across_postures_and_tables() {
        let params = params();
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let coeffs: Vec<Fq> = (0..16).map(|_| Fq::random(&mut rng)).collect();
        let blind = Fq::random(&mut rng);
        let budget = MemoryBudget::DEFAULT;
        let expected = msm_naive::<Ep>(&coeffs, params.g()) + params.w() * blind;
        let public = commit(&params, &coeffs, &blind, Secrecy::Public, budget).expect("msm");
        let secret = commit(&params, &coeffs, &blind, Secrecy::Secret, budget).expect("msm");
        assert_eq!(public, expected);
        assert_eq!(secret, expected);
        let tables = CommitmentTables::build(&params, budget);
        assert_eq!(tables.present(), (true, true));
        assert_eq!(
            tables.commit(&params, &coeffs, &blind, Secrecy::Secret, budget),
            Ok(expected)
        );
        let lagrange = msm_naive::<Ep>(&coeffs, params.g_lagrange()) + params.w() * blind;
        assert_eq!(
            commit_lagrange(&params, &coeffs, &blind, Secrecy::Public, budget),
            Ok(lagrange)
        );
        assert_eq!(
            tables.commit_lagrange(&params, &coeffs, &blind, Secrecy::Public, budget),
            Ok(lagrange)
        );
        // Prefix commitments skip the tables and use g[..m].
        let prefix = commit(&params, &coeffs[..5], &blind, Secrecy::Public, budget).expect("msm");
        assert_eq!(
            prefix,
            msm_naive::<Ep>(&coeffs[..5], &params.g()[..5]) + params.w() * blind
        );
        assert_eq!(
            tables.commit(&params, &coeffs[..5], &blind, Secrecy::Public, budget),
            Ok(prefix)
        );
        let too_long = vec![Fq::ONE; 17];
        assert!(commit(&params, &too_long, &blind, Secrecy::Public, budget).is_err());
        // An all-zero column commits to W, never the identity.
        let zero = commit_lagrange(
            &params,
            &[Fq::ZERO; 16],
            &default_blind(),
            Secrecy::Public,
            budget,
        )
        .expect("msm");
        assert_eq!(zero.to_affine(), params.w());
        assert_eq!(CommitmentTables::<Ep>::default().present(), (false, false));
        assert_eq!(
            CommitmentTables::<Ep>::build(&params, MemoryBudget::new(0)).present(),
            (false, false)
        );
    }

    #[test]
    fn msm_combinations_and_fallback() {
        let params = params();
        let g = params.g();
        let mut msm = Msm::<Ep>::from_point(g[0]);
        msm.push(Fq::from(2), g[1]);
        let mut other = Msm::<Ep>::new();
        other.push(-Fq::ONE, g[0]);
        msm.add_msm(&other);
        msm.scale(&Fq::from(3));
        assert_eq!(msm.len(), 3);
        assert!(!msm.is_empty());
        assert_eq!(msm.terms().count(), 3);
        let expected = g[1].to_curve() * Fq::from(6);
        assert_eq!(msm.evaluate(MemoryBudget::DEFAULT), expected);
        assert_eq!(msm.to_affine(MemoryBudget::DEFAULT), expected.to_affine());
        // A zero budget narrows the window to one bit with the same result.
        let scalars: Vec<Fq> = (1..=16_u64).map(Fq::from).collect();
        assert_eq!(
            msm_complete::<Ep>(&scalars, g, MemoryBudget::new(0)),
            msm_naive::<Ep>(&scalars, g)
        );
        let mut zero = Msm::<Ep>::from_point(g[2]);
        zero.push(-Fq::ONE, g[2]);
        assert!(zero.is_identity(MemoryBudget::DEFAULT));
        assert!(Msm::<Ep>::default().is_identity(MemoryBudget::DEFAULT));
    }
}

#[cfg(test)]
#[path = "commit/bounded_tests.rs"]
mod bounded_tests;
