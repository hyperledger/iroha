//! Multi-scalar multiplication `sum_i scalars[i] * bases[i]`.
//!
//! Entry points:
//!
//! - [`msm_public`]: public scalars (verifier MSMs, commitments to public
//!   data). The window is sized from the actual largest scalar, inversions are
//!   variable time.
//! - [`msm_secret`]: secret scalars (witness commitments). The window is sized
//!   for full 255-bit scalars so the plan does not depend on their magnitude,
//!   the shared bucket inversion is constant time, and digit and bucket
//!   buffers are zeroised. See [`pippenger`] for the remaining timing posture.
//! - [`msm_secret_bounded_cancellable`]: the same secret kernel with a bound
//!   chosen from public protocol data and checked against every scalar before
//!   planning. It does not choose a width from witness values.
//! - [`FixedBaseTable`]: precomputed window multiples of a fixed commitment
//!   key; one bucket set and no doublings per MSM.
//!
//! Every entry point runs on the caller's Rayon pool
//! (`rayon::current_num_threads()` of the pool the call is made from). There is
//! no task blocks on scratch admission. [`MemoryBudget`] limits each kernel,
//! while [`SharedMemoryBudget`] bounds all concurrent MSM scratch in the process
//! to 64 MiB. Contention lowers the plan or selects allocation-free serial
//! multiplication, so nested Rayon work cannot deadlock on memory admission.
//!
//! Results are exact group elements and therefore identical across thread
//! counts, budgets and architectures.

mod budget;
pub mod fixed_base;
pub mod pippenger;

pub use budget::{
    BudgetExceeded, MemoryBudget, PROCESS_MSM_SCRATCH_BYTES, ScratchReservation, SharedMemoryBudget,
};
pub use fixed_base::FixedBaseTable;

use crate::{CancellationToken, Cancelled};
use group::prime::PrimeCurveAffine;
use rayon::prelude::*;
use zeroize::{Zeroize, Zeroizing};

use crate::curve::PastaCurve;
use crate::field::PastaField;

/// MSM failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsmError {
    /// The caller cancelled this MSM; no partial group result is returned.
    Cancelled,
    /// `scalars` and `bases` differ in length.
    LengthMismatch(crate::LengthMismatch),
    /// No window plan fits the memory budget.
    Budget(BudgetExceeded),
    /// A public bit bound exceeds 255, or a scalar does not fit that bound.
    ScalarBound,
    /// More points than the engine indexes (`u32::MAX`).
    TooLarge {
        /// The number of points.
        n: usize,
    },
}

impl core::fmt::Display for MsmError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Cancelled => f.write_str("msm: operation cancelled"),
            Self::LengthMismatch(e) => write!(f, "msm: {e}"),
            Self::Budget(e) => write!(f, "msm: {e}"),
            Self::ScalarBound => f.write_str("msm: scalar exceeds the public bit bound"),
            Self::TooLarge { n } => write!(f, "msm: {n} points exceed the engine limit"),
        }
    }
}

impl std::error::Error for MsmError {}

impl From<Cancelled> for MsmError {
    fn from(_: Cancelled) -> Self {
        Self::Cancelled
    }
}

impl From<BudgetExceeded> for MsmError {
    fn from(e: BudgetExceeded) -> Self {
        Self::Budget(e)
    }
}

/// Below this many points the MSM multiplies point by point.
const SMALL_MSM: usize = 8;

/// Computes `sum_i scalars[i] * bases[i]` for public scalars.
///
/// # Errors
///
/// [`MsmError::LengthMismatch`] for unequal lengths, [`MsmError::Budget`]
/// when no plan fits `budget`, [`MsmError::TooLarge`] beyond `u32::MAX`
/// points.
pub fn msm_public<C: PastaCurve>(
    scalars: &[C::ScalarExt],
    bases: &[C::AffineExt],
    budget: MemoryBudget,
) -> Result<C, MsmError> {
    msm_public_with_shared_budget(
        scalars,
        bases,
        budget,
        &SharedMemoryBudget::process_default(),
    )
}

/// Computes `sum_i scalars[i] * bases[i]` for secret scalars.
///
/// The plan assumes 255-bit scalars regardless of their values, the batch
/// inversions are constant time, and scratch holding digits or bucket sums is
/// zeroised. Bucket selection still follows the digits (see [`pippenger`]).
///
/// # Errors
///
/// As [`msm_public`].
pub fn msm_secret<C: PastaCurve>(
    scalars: &[C::ScalarExt],
    bases: &[C::AffineExt],
    budget: MemoryBudget,
) -> Result<C, MsmError> {
    msm_secret_with_shared_budget(
        scalars,
        bases,
        budget,
        &SharedMemoryBudget::process_default(),
    )
}

/// Public MSM with an explicitly shared caller scratch ceiling.
///
/// Contention may change the execution plan, never the result or input validity.
///
/// # Errors
/// As [`msm_public`]; contention alone does not return an error.
pub fn msm_public_with_shared_budget<C: PastaCurve>(
    scalars: &[C::ScalarExt],
    bases: &[C::AffineExt],
    budget: MemoryBudget,
    shared: &SharedMemoryBudget,
) -> Result<C, MsmError> {
    msm_impl::<C, false>(scalars, bases, budget, shared, None, None)
}

/// Secret MSM with an explicitly shared caller scratch ceiling.
///
/// # Errors
/// As [`msm_secret`]; contention alone does not return an error.
pub fn msm_secret_with_shared_budget<C: PastaCurve>(
    scalars: &[C::ScalarExt],
    bases: &[C::AffineExt],
    budget: MemoryBudget,
    shared: &SharedMemoryBudget,
) -> Result<C, MsmError> {
    msm_impl::<C, true>(scalars, bases, budget, shared, None, None)
}

/// Public MSM with an explicit cancellation signal and scratch ceiling.
///
/// # Errors
/// As [`msm_public`], or [`MsmError::Cancelled`] after all kernel tasks join.
pub fn msm_public_cancellable<C: PastaCurve>(
    scalars: &[C::ScalarExt],
    bases: &[C::AffineExt],
    budget: MemoryBudget,
    shared: &SharedMemoryBudget,
    cancellation: Option<&CancellationToken>,
) -> Result<C, MsmError> {
    msm_impl::<C, false>(scalars, bases, budget, shared, cancellation, None)
}

/// Secret MSM with an explicit cancellation signal and scratch ceiling.
///
/// # Errors
/// As [`msm_secret`], or [`MsmError::Cancelled`]; all secret scratch is wiped
/// and every Rayon task has joined before the error is returned.
pub fn msm_secret_cancellable<C: PastaCurve>(
    scalars: &[C::ScalarExt],
    bases: &[C::AffineExt],
    budget: MemoryBudget,
    shared: &SharedMemoryBudget,
    cancellation: Option<&CancellationToken>,
) -> Result<C, MsmError> {
    msm_impl::<C, true>(scalars, bases, budget, shared, cancellation, None)
}

/// Borrowed secret scalars checked against one independently chosen public bit bound.
///
/// Construction checks every scalar before any small-input, zero-width or scratch
/// fallback can run. It never chooses a width from the values or exposes a private
/// maximum. Callers must derive `bits` from public protocol data, not a witness.
/// This type proves only the numerical bound; it authenticates no protocol data.
/// The borrow prevents mutation of the checked scalars while the proof is held.
pub struct BoundedSecretScalars<'a, F: PastaField> {
    scalars: &'a [F],
    bits: usize,
}

impl<'a, F: PastaField> BoundedSecretScalars<'a, F> {
    /// Check all canonical integers are below `2^bits`, with no allocation.
    /// Zero bits admit only zero. No scalar-dependent early exit or bit-length
    /// scan is used; stack limbs and the accumulated overflow mask are cleared.
    ///
    /// # Errors
    /// [`MsmError::ScalarBound`] for `bits > 255` or any out-of-bound value;
    /// [`MsmError::Cancelled`] at a cooperative chunk boundary.
    pub fn new(
        scalars: &'a [F],
        bits: usize,
        cancellation: Option<&CancellationToken>,
    ) -> Result<Self, MsmError> {
        CancellationToken::checkpoint(cancellation)?;
        if bits > 255 {
            return Err(MsmError::ScalarBound);
        }
        let masks: [u64; 4] = core::array::from_fn(|index| {
            let kept = bits.saturating_sub(index * 64).min(64);
            if kept == 64 { 0 } else { u64::MAX << kept }
        });
        let mut overflow = Zeroizing::new(0_u64);
        for chunk in scalars.chunks(1024) {
            CancellationToken::checkpoint(cancellation)?;
            for scalar in chunk {
                let limbs = Zeroizing::new(scalar.to_canonical_limbs());
                for (limb, mask) in limbs.iter().zip(masks) {
                    *overflow |= limb & mask;
                }
            }
        }
        CancellationToken::checkpoint(cancellation)?;
        if *overflow != 0 {
            return Err(MsmError::ScalarBound);
        }
        Ok(Self { scalars, bits })
    }
}

/// Secret MSM whose window width is bounded by independently public data.
///
/// Uses the same secret kernel: constant-time inversion and clearing of secret
/// scratch. Digit buckets, skips and conflict handling remain variable-time,
/// exactly as in [`msm_secret_cancellable`]. No witness-derived width is chosen.
///
/// # Errors
/// As [`msm_secret_cancellable`]. The checked prefix is already fully validated
/// before this function considers a small/zero-width or scratch fallback.
pub fn msm_secret_bounded_cancellable<C: PastaCurve>(
    scalars: &BoundedSecretScalars<'_, C::ScalarExt>,
    bases: &[C::AffineExt],
    budget: MemoryBudget,
    shared: &SharedMemoryBudget,
    cancellation: Option<&CancellationToken>,
) -> Result<C, MsmError> {
    msm_impl::<C, true>(
        scalars.scalars,
        bases,
        budget,
        shared,
        cancellation,
        Some(scalars.bits),
    )
}

fn msm_impl<C: PastaCurve, const SECRET: bool>(
    scalars: &[C::ScalarExt],
    bases: &[C::AffineExt],
    budget: MemoryBudget,
    shared: &SharedMemoryBudget,
    cancellation: Option<&CancellationToken>,
    public_bits: Option<usize>,
) -> Result<C, MsmError> {
    CancellationToken::checkpoint(cancellation)?;
    if scalars.len() != bases.len() {
        return Err(MsmError::LengthMismatch(crate::LengthMismatch {
            left: scalars.len(),
            right: bases.len(),
        }));
    }
    let n = scalars.len();
    if u32::try_from(n).is_err() {
        return Err(MsmError::TooLarge { n });
    }
    if n == 0 {
        return Ok(C::identity());
    }
    if n <= SMALL_MSM {
        return small_msm::<C, SECRET>(scalars, bases, cancellation);
    }
    let bits = if SECRET {
        public_bits.unwrap_or(255)
    } else {
        scalars
            .par_iter()
            .map(PastaField::bit_length_vartime)
            .max()
            .unwrap_or(0) as usize
    };
    if bits == 0 {
        return Ok(C::identity());
    }
    let threads = rayon::current_num_threads();
    let mut plan = pippenger::plan(n, bits, threads, budget.bytes()).ok_or_else(|| {
        MsmError::Budget(BudgetExceeded {
            required: pippenger::min_plan_bytes(n, bits),
            budget: budget.bytes(),
        })
    })?;
    // Never wait with a Rayon worker occupied: another kernel may need this
    // worker to finish and release its own permit. A lost admission race has
    // the same allocation-free fallback as an exhausted shared ceiling.
    if plan.bytes > shared.available_bytes() {
        let Some(smaller) = pippenger::plan(
            n,
            bits,
            threads,
            budget.bytes().min(shared.available_bytes()),
        ) else {
            return small_msm::<C, SECRET>(scalars, bases, cancellation);
        };
        plan = smaller;
    }
    let Some(_scratch) = shared.try_reserve(plan.bytes) else {
        return small_msm::<C, SECRET>(scalars, bases, cancellation);
    };
    // Identity bases contribute nothing and would break the affine formulas.
    let skip: Vec<bool> = bases.iter().map(|b| bool::from(b.is_identity())).collect();
    let digits = pippenger::Digits::new_cancellable(scalars, plan.c, plan.nw, cancellation)?;
    let tasks = plan.groups * plan.chunks;
    // Waves of at most `plan.concurrency` tasks bound the live bucket memory.
    let mut windows = Zeroizing::new(vec![C::identity(); plan.nw]);
    for start in (0..tasks).step_by(plan.concurrency) {
        CancellationToken::checkpoint(cancellation)?;
        let mut results: Vec<(usize, Zeroizing<Vec<C>>)> = (start
            ..(start + plan.concurrency).min(tasks))
            .into_par_iter()
            .map(|task| {
                pippenger::run_task_cancellable::<C, SECRET>(
                    bases,
                    &skip,
                    &digits,
                    &plan,
                    task / plan.chunks,
                    task % plan.chunks,
                    cancellation,
                )
            })
            .collect();
        CancellationToken::checkpoint(cancellation)?;
        for (w0, sums) in &mut results {
            for (k, s) in sums.iter().enumerate() {
                windows[*w0 + k] += s;
            }
            if SECRET {
                sums.zeroize();
            }
        }
    }
    let result = pippenger::combine(&windows, plan.c);
    if SECRET {
        windows.zeroize();
    }
    CancellationToken::checkpoint(cancellation)?;
    Ok(result)
}

/// Point-by-point MSM for tiny inputs.
fn small_msm<C: PastaCurve, const SECRET: bool>(
    scalars: &[C::ScalarExt],
    bases: &[C::AffineExt],
    cancellation: Option<&CancellationToken>,
) -> Result<C, MsmError> {
    let mut acc = Zeroizing::new(C::identity());
    for (s, b) in scalars.iter().zip(bases.iter()) {
        CancellationToken::checkpoint(cancellation)?;
        let p = b.to_curve();
        // The public GLV multiplier allocates wNAF digit vectors. Use the
        // stack-only complete multiplier for both modes: this path also runs
        // when the shared scratch ceiling has no free bytes.
        *acc += p * *s;
    }
    CancellationToken::checkpoint(cancellation)?;
    Ok(*acc)
}

/// Reference MSM by independent scalar multiplications (tests and
/// differential checks).
pub fn msm_naive<C: PastaCurve>(scalars: &[C::ScalarExt], bases: &[C::AffineExt]) -> C {
    scalars
        .iter()
        .zip(bases.iter())
        .fold(C::identity(), |acc, (s, b)| acc + b.to_curve() * *s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::{Ep, EpAffine};
    use crate::field::Fq;
    use ff::Field;
    use group::{Curve, Group};
    use rand_chacha::ChaCha20Rng;
    use rand_core_06::SeedableRng;

    fn shared_msm_parity<C: PastaCurve>() {
        let scalars = (0..48)
            .map(|i| match i % 3 {
                0 => C::ScalarExt::ZERO,
                1 => -C::ScalarExt::ONE,
                _ => C::ScalarExt::from(i + 1),
            })
            .collect::<Vec<_>>();
        let bases = (0..48)
            .map(|i| match i % 4 {
                0 => C::AffineExt::identity(),
                1 => C::generator().to_affine(),
                2 => (-C::generator()).to_affine(),
                _ => (C::generator() * C::ScalarExt::from(i + 1)).to_affine(),
            })
            .collect::<Vec<_>>();
        let expected = msm_naive::<C>(&scalars, &bases).to_affine();
        let shared = SharedMemoryBudget::new(128 << 10);
        for threads in [1, 4] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap();
            // Holding the complete caller budget while entering nested Rayon
            // work must not wait for this same stack frame to release it.
            let held = shared.try_reserve(shared.limit_bytes()).unwrap();
            pool.install(|| {
                rayon::join(
                    || {
                        assert_eq!(
                            msm_public_with_shared_budget::<C>(
                                &scalars,
                                &bases,
                                MemoryBudget::DEFAULT,
                                &shared
                            )
                            .unwrap()
                            .to_affine(),
                            expected
                        )
                    },
                    || {
                        assert_eq!(
                            msm_secret_with_shared_budget::<C>(
                                &scalars,
                                &bases,
                                MemoryBudget::DEFAULT,
                                &shared
                            )
                            .unwrap()
                            .to_affine(),
                            expected
                        )
                    },
                );
            });
            drop(held);
            pool.install(|| {
                (0..8).into_par_iter().for_each(|_| {
                    assert_eq!(
                        msm_secret_with_shared_budget::<C>(
                            &scalars,
                            &bases,
                            MemoryBudget::DEFAULT,
                            &shared
                        )
                        .unwrap()
                        .to_affine(),
                        expected
                    );
                });
            });
            assert_eq!(shared.in_use_bytes(), 0);
            assert!(shared.peak_bytes() <= shared.limit_bytes());
        }
    }

    #[test]
    fn shared_budget_preserves_both_curves_under_nested_contention() {
        shared_msm_parity::<Ep>();
        shared_msm_parity::<crate::Eq>();
    }

    #[test]
    fn small_and_large_agree_with_naive() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        for n in [0usize, 1, 5, 9, 100] {
            let bases: Vec<EpAffine> = (0..n).map(|_| Ep::random(&mut rng).to_affine()).collect();
            let scalars: Vec<Fq> = (0..n).map(|_| Fq::random(&mut rng)).collect();
            let expected = msm_naive::<Ep>(&scalars, &bases);
            assert_eq!(
                msm_public::<Ep>(&scalars, &bases, MemoryBudget::DEFAULT).unwrap(),
                expected
            );
            assert_eq!(
                msm_secret::<Ep>(&scalars, &bases, MemoryBudget::DEFAULT).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn errors() {
        let b = [EpAffine::default()];
        let err = msm_public::<Ep>(&[], &b, MemoryBudget::DEFAULT).unwrap_err();
        assert!(matches!(err, MsmError::LengthMismatch(_)));
        let mut rng = ChaCha20Rng::seed_from_u64(4);
        let bases: Vec<EpAffine> = (0..64).map(|_| Ep::random(&mut rng).to_affine()).collect();
        let scalars: Vec<Fq> = (0..64).map(|_| Fq::random(&mut rng)).collect();
        let err = msm_public::<Ep>(&scalars, &bases, MemoryBudget::new(16)).unwrap_err();
        assert!(matches!(err, MsmError::Budget(_)));
        assert!(err.to_string().starts_with("msm: kernel needs"));
        assert_eq!(
            MsmError::from(BudgetExceeded {
                required: 1,
                budget: 0
            }),
            MsmError::Budget(BudgetExceeded {
                required: 1,
                budget: 0
            })
        );
        assert_eq!(
            small_msm::<Ep, false>(&scalars[..2], &bases[..2], None).unwrap(),
            msm_naive::<Ep>(&scalars[..2], &bases[..2])
        );
    }
}

#[cfg(test)]
mod bounded_tests;
