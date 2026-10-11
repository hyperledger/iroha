//! Fixed-base MSM with precomputed window tables (commitment keys).
//!
//! For bases `P_i` and window width `c`, the table stores `2^(c w) * P_i` for
//! every window `w`, as affine points in layout `[i * nw + w]`. An MSM then
//! drops every scalar digit into a single set of `2^(c-1)` buckets: there are
//! no per-window bucket sets and no doublings. The table costs
//! `n * nw * 64` bytes (about 2.6 MiB for `n = 2^11, c = 13` and about 84 MiB
//! for `n = 2^16`), so its construction is gated by a [`MemoryBudget`].
//!
//! # Memory
//!
//! Construction is charged for everything it holds at once: the final table,
//! one skip flag per base, and the projective build scratch. Rows are built
//! and normalised in chunks of about [`BUILD_CHUNK_ENTRIES`] entries straight
//! into the final table, so the scratch is bounded by the chunk size rather
//! than by the table (160 bytes per entry while a chunk is built: the
//! projective point, its inverted `z` and the batch-inversion prefix). As many
//! chunks run at once as the budget leaves room for, at most one per Rayon
//! worker; whether construction succeeds depends only on the bases, the window
//! and the budget, never on the pool size.
//!
//! An MSM against the table holds the scalar digits and one bucket set per
//! task. The number of tasks is lowered to fit the budget, so an MSM fails
//! only when a single task does not fit, again independently of the pool size.
//!
//! Tables are built from public bases with exact arithmetic; MSM results equal
//! the variable-base MSM bit for bit.

use crate::CancellationToken;
use group::prime::PrimeCurveAffine;
use rayon::prelude::*;
use zeroize::Zeroizing;

use super::pippenger::{Buckets, Digits, MAX_WINDOW, bucket_bytes, num_windows};
use super::{BudgetExceeded, MemoryBudget, MsmError, SharedMemoryBudget};
use crate::curve::PastaCurve;

/// Window multiples of a fixed set of bases.
#[derive(Clone, Debug)]
pub struct FixedBaseTable<C: PastaCurve> {
    c: usize,
    nw: usize,
    n: usize,
    points: Vec<C::AffineExt>,
    skip: Vec<bool>,
}

/// Smallest window the automatic choice considers.
const AUTO_MIN_WINDOW: usize = 8;
/// Largest window the automatic choice considers.
const AUTO_MAX_WINDOW: usize = 14;
/// Table entries built and normalised together during construction.
pub const BUILD_CHUNK_ENTRIES: usize = 4096;
/// Bases of one MSM task below which the table MSM does not split further.
const MIN_BASES_PER_TASK: usize = 256;

/// Bytes of the finished table for `n` bases with window `c`.
fn table_bytes<C: PastaCurve>(n: usize, c: usize) -> Option<usize> {
    n.checked_mul(num_windows(255, c))?
        .checked_mul(core::mem::size_of::<C::AffineExt>())
}

/// Transient bytes per table entry while its chunk is built: the projective
/// point, its inverted `z` coordinate and the batch-inversion prefix.
fn build_entry_bytes<C: PastaCurve>() -> usize {
    core::mem::size_of::<C>() + 2 * core::mem::size_of::<C::Base>()
}

/// Bases per construction chunk for `nw` windows (at least one).
fn build_rows(nw: usize) -> usize {
    (BUILD_CHUNK_ENTRIES / nw.max(1)).max(1)
}

/// Memory a construction with window `c` holds at once: `(fixed, chunk)` where
/// `fixed` is the table plus the skip flags and `chunk` is the scratch of one
/// construction chunk. `None` when the table is too large to index.
fn build_bytes<C: PastaCurve>(n: usize, c: usize) -> Option<(usize, usize)> {
    let nw = num_windows(255, c);
    // The bucket engine indexes table points with u32.
    u32::try_from(n.checked_mul(nw)?).ok()?;
    let fixed = table_bytes::<C>(n, c)?.checked_add(n)?;
    let chunk = build_rows(nw)
        .min(n)
        .checked_mul(nw)?
        .checked_mul(build_entry_bytes::<C>())?;
    Some((fixed, chunk))
}

/// The smallest budget a construction with window `c` needs.
fn required_bytes<C: PastaCurve>(n: usize, c: usize) -> Option<usize> {
    let (fixed, chunk) = build_bytes::<C>(n, c)?;
    fixed.checked_add(chunk)
}

/// Fills `out` (layout `[row * nw + w]`) with `2^(c w) * rows[row]`, through a
/// projective scratch of `out.len()` points normalised with one inversion.
fn build_chunk<C: PastaCurve, E>(
    rows: &[C::AffineExt],
    c: usize,
    out: &mut [C::AffineExt],
    checkpoint: &impl Fn() -> Result<(), E>,
) -> Result<(), E> {
    checkpoint()?;
    let nw = out.len() / rows.len().max(1);
    let mut projective = Vec::with_capacity(out.len());
    for base in rows {
        checkpoint()?;
        let mut cur = base.to_curve();
        for w in 0..nw {
            projective.push(cur);
            if w + 1 < nw {
                for _ in 0..c {
                    cur = cur.double();
                }
            }
        }
    }
    checkpoint()?;
    crate::curve::normalize_vartime_into(&projective, out);
    checkpoint()
}

impl<C: PastaCurve> FixedBaseTable<C> {
    /// Builds a table, choosing the window from a cost model among the windows
    /// whose construction fits `budget`.
    ///
    /// # Errors
    ///
    /// [`BudgetExceeded`] when no considered window fits; `required` is the
    /// smallest budget that some window would accept.
    pub fn new(bases: &[C::AffineExt], budget: MemoryBudget) -> Result<Self, BudgetExceeded> {
        Self::new_with_shared_budget(bases, budget, &SharedMemoryBudget::process_default())
    }

    /// Build a table with an additional shared construction-scratch ceiling.
    ///
    /// The retained table belongs to the caller's `budget`; temporary chunk
    /// buffers additionally charge `shared` and the process-wide scratch cap.
    ///
    /// # Errors
    /// As [`Self::new`].
    pub fn new_with_shared_budget(
        bases: &[C::AffineExt],
        budget: MemoryBudget,
        shared: &SharedMemoryBudget,
    ) -> Result<Self, BudgetExceeded> {
        Self::new_impl(bases, budget, shared, &|| Ok::<(), BudgetExceeded>(()))
    }

    /// Build public fixed-base tables with cancellation at bounded construction tasks.
    ///
    /// # Errors
    /// Budget refusal as [`Self::new`], or [`MsmError::Cancelled`] after all tasks join.
    pub fn new_cancellable(
        bases: &[C::AffineExt],
        budget: MemoryBudget,
        cancellation: Option<&CancellationToken>,
    ) -> Result<Self, MsmError> {
        Self::new_impl(
            bases,
            budget,
            &SharedMemoryBudget::process_default(),
            &|| CancellationToken::checkpoint(cancellation).map_err(MsmError::from),
        )
    }

    fn new_impl<E: From<BudgetExceeded> + Send>(
        bases: &[C::AffineExt],
        budget: MemoryBudget,
        shared: &SharedMemoryBudget,
        checkpoint: &(impl Fn() -> Result<(), E> + Sync),
    ) -> Result<Self, E> {
        checkpoint()?;
        let n = bases.len();
        let mut best: Option<(u128, usize)> = None;
        let mut smallest = usize::MAX;
        for c in AUTO_MIN_WINDOW..=AUTO_MAX_WINDOW {
            let Some(bytes) = required_bytes::<C>(n, c) else {
                continue;
            };
            smallest = smallest.min(bytes);
            if bytes > budget.bytes() {
                continue;
            }
            let nw = num_windows(255, c) as u128;
            // Batch-affine additions plus one bucket reduction per worker.
            let cost = (n as u128) * nw * 6
                + (1u128 << (c - 1)) * 25 * (rayon::current_num_threads() as u128);
            if best.is_none_or(|(b, _)| cost < b) {
                best = Some((cost, c));
            }
        }
        let Some((_, c)) = best else {
            return Err(BudgetExceeded {
                required: smallest,
                budget: budget.bytes(),
            }
            .into());
        };
        Self::with_window_impl(bases, c, budget, shared, checkpoint)
    }

    /// Builds a table with window width `c` (clamped to `2..=15`).
    ///
    /// The budget covers the finished table, the skip flags and the
    /// construction scratch (see the module documentation).
    ///
    /// # Errors
    ///
    /// [`BudgetExceeded`] when the construction does not fit `budget`.
    pub fn with_window(
        bases: &[C::AffineExt],
        c: usize,
        budget: MemoryBudget,
    ) -> Result<Self, BudgetExceeded> {
        Self::with_window_and_shared_budget(
            bases,
            c,
            budget,
            &SharedMemoryBudget::process_default(),
        )
    }

    /// Build the requested window table with shared construction admission.
    ///
    /// When no chunk fits the currently available shared scratch, normalize
    /// points individually without allocating construction scratch.
    ///
    /// # Errors
    /// As [`Self::with_window`].
    pub fn with_window_and_shared_budget(
        bases: &[C::AffineExt],
        c: usize,
        budget: MemoryBudget,
        shared: &SharedMemoryBudget,
    ) -> Result<Self, BudgetExceeded> {
        Self::with_window_impl(bases, c, budget, shared, &|| Ok::<(), BudgetExceeded>(()))
    }

    fn with_window_impl<E: From<BudgetExceeded> + Send>(
        bases: &[C::AffineExt],
        c: usize,
        budget: MemoryBudget,
        shared: &SharedMemoryBudget,
        checkpoint: &(impl Fn() -> Result<(), E> + Sync),
    ) -> Result<Self, E> {
        checkpoint()?;
        let c = c.clamp(2, MAX_WINDOW);
        let n = bases.len();
        let nw = num_windows(255, c);
        // Tables the bucket engine cannot index exceed every budget.
        let Some((fixed, chunk)) = build_bytes::<C>(n, c) else {
            return Err(BudgetExceeded {
                required: usize::MAX,
                budget: budget.bytes(),
            }
            .into());
        };
        budget.check(fixed.saturating_add(chunk))?;
        // Chunks built at the same time: as many as the budget leaves room
        // for, at most one per worker and at least one.
        let room = budget
            .bytes()
            .saturating_sub(fixed)
            .min(shared.available_bytes());
        let concurrency = room
            .checked_div(chunk)
            .unwrap_or(usize::MAX)
            .clamp(1, rayon::current_num_threads().max(1));
        let rows = build_rows(nw);
        let scratch = shared.try_reserve(chunk.saturating_mul(concurrency));
        let mut points = vec![C::AffineExt::default(); n * nw];
        if scratch.is_some() {
            // Iterate waves directly, without a heap vector of job descriptors.
            for (out, wave_bases) in points
                .chunks_mut(rows * nw * concurrency)
                .zip(bases.chunks(rows * concurrency))
            {
                checkpoint()?;
                out.par_chunks_mut(rows * nw)
                    .zip(wave_bases.par_chunks(rows))
                    .try_for_each(|(out, chunk_bases)| {
                        build_chunk::<C, E>(chunk_bases, c, out, checkpoint)
                    })?;
            }
        } else {
            for (out, base) in points.chunks_mut(nw).zip(bases) {
                checkpoint()?;
                let mut point = base.to_curve();
                for (window, slot) in out.iter_mut().enumerate() {
                    *slot = point.to_affine();
                    if window + 1 < nw {
                        for _ in 0..c {
                            point = point.double();
                        }
                    }
                }
            }
        }
        checkpoint()?;
        let skip = bases
            .iter()
            .enumerate()
            .map(|(index, base)| {
                if index % 1024 == 0 {
                    checkpoint()?;
                }
                Ok(bool::from(base.is_identity()))
            })
            .collect::<Result<Vec<_>, E>>()?;
        checkpoint()?;
        Ok(Self {
            c,
            nw,
            n,
            points,
            skip,
        })
    }

    /// The window width.
    pub fn window(&self) -> usize {
        self.c
    }

    /// The number of bases.
    pub fn len(&self) -> usize {
        self.n
    }

    /// Whether the table has no bases.
    pub fn is_empty(&self) -> bool {
        self.n == 0
    }

    /// Bytes held by the table points.
    pub fn table_bytes(&self) -> usize {
        self.points
            .len()
            .saturating_mul(core::mem::size_of::<C::AffineExt>())
    }

    /// MSM with public scalars against the table bases.
    ///
    /// # Errors
    ///
    /// [`MsmError::LengthMismatch`] unless `scalars.len()` equals the number of
    /// bases; [`MsmError::Budget`] when the digits and a single task's bucket
    /// set exceed `budget` (independent of the pool size).
    pub fn msm_public(
        &self,
        scalars: &[C::ScalarExt],
        budget: MemoryBudget,
    ) -> Result<C, MsmError> {
        self.msm_public_with_shared_budget(scalars, budget, &SharedMemoryBudget::process_default())
    }

    /// MSM with secret scalars: constant-time batch inversion and zeroised
    /// scratch, with the bucket-selection posture described in
    /// [`super::pippenger`].
    ///
    /// # Errors
    ///
    /// As [`Self::msm_public`].
    pub fn msm_secret(
        &self,
        scalars: &[C::ScalarExt],
        budget: MemoryBudget,
    ) -> Result<C, MsmError> {
        self.msm_secret_with_shared_budget(scalars, budget, &SharedMemoryBudget::process_default())
    }

    /// Public table MSM charging an explicit shared scratch ceiling.
    ///
    /// # Errors
    /// As [`Self::msm_public`]; contention selects an allocation-free fallback.
    pub fn msm_public_with_shared_budget(
        &self,
        scalars: &[C::ScalarExt],
        budget: MemoryBudget,
        shared: &SharedMemoryBudget,
    ) -> Result<C, MsmError> {
        self.msm_impl::<false>(scalars, budget, shared, None)
    }

    /// Secret table MSM charging an explicit shared scratch ceiling.
    ///
    /// # Errors
    /// As [`Self::msm_secret`]; contention selects an allocation-free fallback.
    pub fn msm_secret_with_shared_budget(
        &self,
        scalars: &[C::ScalarExt],
        budget: MemoryBudget,
        shared: &SharedMemoryBudget,
    ) -> Result<C, MsmError> {
        self.msm_impl::<true>(scalars, budget, shared, None)
    }

    /// Public table MSM with explicit cancellation and shared scratch.
    ///
    /// # Errors
    /// As [`Self::msm_public`], or [`MsmError::Cancelled`] after tasks join.
    pub fn msm_public_cancellable(
        &self,
        scalars: &[C::ScalarExt],
        budget: MemoryBudget,
        shared: &SharedMemoryBudget,
        cancellation: Option<&CancellationToken>,
    ) -> Result<C, MsmError> {
        self.msm_impl::<false>(scalars, budget, shared, cancellation)
    }

    /// Secret table MSM with explicit cancellation and shared scratch.
    ///
    /// # Errors
    /// As [`Self::msm_secret`], or [`MsmError::Cancelled`]. Secret scratch is
    /// wiped and all tasks have joined before the error is returned.
    pub fn msm_secret_cancellable(
        &self,
        scalars: &[C::ScalarExt],
        budget: MemoryBudget,
        shared: &SharedMemoryBudget,
        cancellation: Option<&CancellationToken>,
    ) -> Result<C, MsmError> {
        self.msm_impl::<true>(scalars, budget, shared, cancellation)
    }

    /// Scratch of one MSM: `(digit_bytes, bucket_bytes)` where the second is
    /// one task's bucket set.
    fn msm_scratch(&self) -> (usize, usize) {
        let nb = 1usize << (self.c - 1);
        let digits = self.n.saturating_mul(self.nw).saturating_mul(2);
        (
            digits,
            bucket_bytes(nb)
                .unwrap_or(usize::MAX)
                .saturating_add(size_of::<C>()),
        )
    }

    /// Number of MSM tasks for `threads` workers within `budget`, or the
    /// budget error when even one task does not fit.
    fn msm_tasks(&self, threads: usize, budget: MemoryBudget) -> Result<usize, BudgetExceeded> {
        let (digits, buckets) = self.msm_scratch();
        budget.check(digits.saturating_add(buckets))?;
        let affordable = budget
            .bytes()
            .saturating_sub(digits)
            .checked_div(buckets)
            .unwrap_or(usize::MAX);
        Ok(threads
            .max(1)
            .min(self.n.div_ceil(MIN_BASES_PER_TASK))
            .min(affordable)
            .max(1))
    }

    fn msm_impl<const SECRET: bool>(
        &self,
        scalars: &[C::ScalarExt],
        budget: MemoryBudget,
        shared: &SharedMemoryBudget,
        cancellation: Option<&CancellationToken>,
    ) -> Result<C, MsmError> {
        CancellationToken::checkpoint(cancellation)?;
        if scalars.len() != self.n {
            return Err(MsmError::LengthMismatch(crate::LengthMismatch {
                left: scalars.len(),
                right: self.n,
            }));
        }
        if self.n == 0 {
            return Ok(C::identity());
        }
        let nb = 1usize << (self.c - 1);
        let threads = rayon::current_num_threads();
        let mut tasks = self.msm_tasks(threads, budget)?;
        let (digits_bytes, task_bytes) = self.msm_scratch();
        let available = MemoryBudget::new(budget.bytes().min(shared.available_bytes()));
        if let Ok(smaller) = self.msm_tasks(threads, available) {
            tasks = tasks.min(smaller);
        }
        let Some(_scratch) =
            shared.try_reserve(digits_bytes.saturating_add(tasks.saturating_mul(task_bytes)))
        else {
            let mut result = Zeroizing::new(C::identity());
            for (i, scalar) in scalars.iter().enumerate() {
                CancellationToken::checkpoint(cancellation)?;
                *result += self.points[i * self.nw].to_curve() * *scalar;
            }
            CancellationToken::checkpoint(cancellation)?;
            return Ok(*result);
        };
        let digits = Digits::new_cancellable(scalars, self.c, self.nw, cancellation)?;
        let step = self.n.div_ceil(tasks);
        let mut partial = Zeroizing::new(
            (0..tasks)
                .into_par_iter()
                .map(|t| {
                    if CancellationToken::checkpoint(cancellation).is_err() {
                        return C::identity();
                    }
                    let mut buckets = Buckets::<C, SECRET>::new(&self.points, nb);
                    let i1 = ((t + 1) * step).min(self.n);
                    for i in t * step..i1 {
                        if i % 256 == 0 && CancellationToken::checkpoint(cancellation).is_err() {
                            return C::identity();
                        }
                        if self.skip[i] {
                            continue;
                        }
                        for (w, &d) in digits.row(i).iter().enumerate() {
                            if d != 0 {
                                buckets.insert(
                                    usize::from(d.unsigned_abs()) - 1,
                                    i * self.nw + w,
                                    d < 0,
                                );
                            }
                        }
                    }
                    buckets.flush();
                    // Dropping `buckets` wipes its scratch in secret mode.
                    buckets.reduce(0, nb)
                })
                .collect::<Vec<C>>(),
        );
        CancellationToken::checkpoint(cancellation)?;
        let result = partial.iter().fold(C::identity(), |acc, p| acc + p);
        if SECRET {
            zeroize::Zeroize::zeroize(&mut partial);
        }
        Ok(result)
    }

    /// The table point `2^(c w) * P_i` (tests and diagnostics).
    pub fn entry(&self, i: usize, w: usize) -> Option<C::AffineExt> {
        if i < self.n && w < self.nw {
            self.points.get(i * self.nw + w).copied()
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn cancelled_table_construction_joins_tasks_releases_scratch_and_retries() {
        fn check<C: PastaCurve>() {
            use std::sync::atomic::{AtomicUsize, Ordering};
            let mut rng = ChaCha20Rng::seed_from_u64(197);
            let bases = (0..450)
                .map(|_| C::random(&mut rng).to_affine())
                .collect::<Vec<_>>();
            // More than two chunks; both the shared-scratch path and its zero-budget
            // scalar fallback must unwind before this call returns.
            for shared_limit in [0, MemoryBudget::DEFAULT.bytes()] {
                let shared = SharedMemoryBudget::new(shared_limit);
                let token = CancellationToken::new();
                let calls = AtomicUsize::new(0);
                let result = pool(4).install(|| {
                    FixedBaseTable::<C>::with_window_impl(
                        &bases,
                        13,
                        MemoryBudget::DEFAULT,
                        &shared,
                        &|| {
                            if calls.fetch_add(1, Ordering::AcqRel) == 17 {
                                token.cancel();
                            }
                            token.check().map_err(MsmError::from)
                        },
                    )
                });
                assert!(matches!(result, Err(MsmError::Cancelled)));
                assert!(calls.load(Ordering::Acquire) >= 18);
                assert_eq!(shared.in_use_bytes(), 0);
                if shared_limit == 0 {
                    assert_eq!(shared.peak_bytes(), 0);
                } else {
                    assert!(shared.peak_bytes() > 0);
                }
                let retry = pool(4)
                    .install(|| {
                        FixedBaseTable::<C>::with_window_and_shared_budget(
                            &bases,
                            13,
                            MemoryBudget::DEFAULT,
                            &shared,
                        )
                    })
                    .unwrap();
                let expected =
                    FixedBaseTable::<C>::with_window(&bases, 13, MemoryBudget::DEFAULT).unwrap();
                assert_eq!(retry.points, expected.points);
                assert_eq!(retry.skip, expected.skip);
                assert_eq!(shared.in_use_bytes(), 0);
                assert!(matches!(
                    FixedBaseTable::<C>::new_cancellable(
                        &bases,
                        MemoryBudget::DEFAULT,
                        Some(&token)
                    ),
                    Err(MsmError::Cancelled)
                ));
                let fresh = CancellationToken::new();
                let ordinary = FixedBaseTable::<C>::new(&bases, MemoryBudget::DEFAULT).unwrap();
                let cancellable = FixedBaseTable::<C>::new_cancellable(
                    &bases,
                    MemoryBudget::DEFAULT,
                    Some(&fresh),
                )
                .unwrap();
                assert_eq!(ordinary.points, cancellable.points);
                assert_eq!(ordinary.skip, cancellable.skip);
            }
        }
        check::<crate::Ep>();
        check::<crate::Eq>();
    }

    use super::*;
    use crate::curve::{Eq, EqAffine};
    use crate::field::Fp;
    use crate::msm::msm_naive;
    use ff::Field;
    use group::{Curve, Group};
    use rand_chacha::ChaCha20Rng;
    use rand_core_06::SeedableRng;

    #[test]
    fn shared_budget_fallback_preserves_table_and_msm() {
        let bases = (1..24)
            .map(|i| (Eq::generator() * crate::Fp::from(i)).to_affine())
            .collect::<Vec<_>>();
        let scalars = (1..24).map(|i| -crate::Fp::from(i)).collect::<Vec<_>>();
        let shared = SharedMemoryBudget::new(0);
        let ordinary = FixedBaseTable::<Eq>::with_window(&bases, 8, MemoryBudget::DEFAULT).unwrap();
        let fallback = FixedBaseTable::<Eq>::with_window_and_shared_budget(
            &bases,
            8,
            MemoryBudget::DEFAULT,
            &shared,
        )
        .unwrap();
        assert_eq!(ordinary.points, fallback.points);
        let automatic =
            FixedBaseTable::<Eq>::new_with_shared_budget(&bases, MemoryBudget::DEFAULT, &shared)
                .unwrap();
        let expected = msm_naive::<Eq>(&scalars, &bases).to_affine();
        for table in [&ordinary, &fallback, &automatic] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(1)
                .build()
                .unwrap();
            pool.install(|| {
                rayon::join(
                    || {
                        assert_eq!(
                            table
                                .msm_public_with_shared_budget(
                                    &scalars,
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
                            table
                                .msm_secret_with_shared_budget(
                                    &scalars,
                                    MemoryBudget::DEFAULT,
                                    &shared
                                )
                                .unwrap()
                                .to_affine(),
                            expected
                        )
                    },
                )
            });
        }
        assert_eq!(shared.in_use_bytes(), 0);
        assert_eq!(shared.peak_bytes(), 0);
    }
    #[test]
    fn table_msm_matches_naive() {
        let mut rng = ChaCha20Rng::seed_from_u64(8);
        let mut bases: Vec<EqAffine> = (0..300).map(|_| Eq::random(&mut rng).to_affine()).collect();
        bases[10] = EqAffine::default();
        let scalars: Vec<Fp> = (0..300).map(|_| Fp::random(&mut rng)).collect();
        let expected = msm_naive::<Eq>(&scalars, &bases);
        for c in [4usize, 9, 13] {
            let t = FixedBaseTable::<Eq>::with_window(&bases, c, MemoryBudget::DEFAULT).unwrap();
            assert_eq!(t.window(), c);
            assert_eq!(t.len(), 300);
            assert!(!t.is_empty());
            assert_eq!(
                t.msm_public(&scalars, MemoryBudget::DEFAULT).unwrap(),
                expected
            );
            assert_eq!(
                t.msm_secret(&scalars, MemoryBudget::DEFAULT).unwrap(),
                expected
            );
            assert_eq!(t.entry(3, 0), Some(bases[3]));
        }
        let auto = FixedBaseTable::<Eq>::new(&bases, MemoryBudget::DEFAULT).unwrap();
        assert!(auto.table_bytes() > 0);
        assert!(auto.entry(300, 0).is_none());
        assert!(FixedBaseTable::<Eq>::new(&bases, MemoryBudget::new(10)).is_err());
        assert!(
            auto.msm_public(&scalars[..3], MemoryBudget::DEFAULT)
                .is_err()
        );
    }

    fn pool(threads: usize) -> rayon::ThreadPool {
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .expect("thread pool")
    }

    #[test]
    fn construction_budget_covers_table_flags_and_chunk_scratch() {
        let mut rng = ChaCha20Rng::seed_from_u64(9);
        // More than one construction chunk (4096 / 20 = 204 rows per chunk).
        let bases: Vec<EqAffine> = (0..450).map(|_| Eq::random(&mut rng).to_affine()).collect();
        let c = 13;
        let nw = num_windows(255, c);
        let (fixed, chunk) = build_bytes::<Eq>(bases.len(), c).unwrap();
        assert_eq!(fixed, bases.len() * nw * 64 + bases.len());
        assert_eq!(chunk, build_rows(nw) * nw * (96 + 32 + 32));
        assert_eq!(build_entry_bytes::<Eq>(), 160);
        // The old check charged only the table; the transient chunk scratch
        // must now fit as well.
        let table_only = MemoryBudget::new(fixed);
        assert_eq!(
            FixedBaseTable::<Eq>::with_window(&bases, c, table_only).unwrap_err(),
            BudgetExceeded {
                required: fixed + chunk,
                budget: fixed
            }
        );
        let exact = MemoryBudget::new(fixed + chunk);
        let reference =
            FixedBaseTable::<Eq>::with_window(&bases, c, MemoryBudget::DEFAULT).unwrap();
        for threads in [1usize, 2, 7] {
            // The exact budget admits one chunk at a time on every pool.
            let built = pool(threads)
                .install(|| FixedBaseTable::<Eq>::with_window(&bases, c, exact))
                .unwrap();
            assert_eq!(built.points, reference.points, "threads = {threads}");
            assert_eq!(built.skip, reference.skip);
        }
        for w in [0, 1, nw - 1] {
            let mut expected = bases[449].to_curve();
            for _ in 0..c * w {
                expected = expected.double();
            }
            assert_eq!(reference.entry(449, w), Some(expected.to_affine()));
        }
        assert!(required_bytes::<Eq>(usize::MAX, c).is_none());
        assert!(FixedBaseTable::<Eq>::with_window(&[], c, MemoryBudget::new(0)).is_ok());
    }

    #[test]
    fn auto_window_reports_the_smallest_feasible_budget() {
        let mut rng = ChaCha20Rng::seed_from_u64(10);
        let bases: Vec<EqAffine> = (0..64).map(|_| Eq::random(&mut rng).to_affine()).collect();
        let err = FixedBaseTable::<Eq>::new(&bases, MemoryBudget::new(1)).unwrap_err();
        let smallest = (AUTO_MIN_WINDOW..=AUTO_MAX_WINDOW)
            .filter_map(|c| required_bytes::<Eq>(64, c))
            .min()
            .unwrap();
        assert_eq!(err.required, smallest);
        assert!(FixedBaseTable::<Eq>::new(&bases, MemoryBudget::new(smallest)).is_ok());
    }

    #[test]
    fn msm_feasibility_does_not_depend_on_the_pool_size() {
        let mut rng = ChaCha20Rng::seed_from_u64(11);
        let n = 600;
        let bases: Vec<EqAffine> = (0..n).map(|_| Eq::random(&mut rng).to_affine()).collect();
        let scalars: Vec<Fp> = (0..n).map(|_| Fp::random(&mut rng)).collect();
        let expected = msm_naive::<Eq>(&scalars, &bases);
        let table = FixedBaseTable::<Eq>::with_window(&bases, 13, MemoryBudget::DEFAULT).unwrap();
        let (digits, buckets) = table.msm_scratch();
        // Room for exactly one task's buckets: 7 workers would want 3 tasks.
        let tight = MemoryBudget::new(digits + buckets);
        let short = MemoryBudget::new(digits + buckets - 1);
        for threads in [1usize, 7] {
            let p = pool(threads);
            assert_eq!(p.install(|| table.msm_tasks(threads, tight)), Ok(1));
            assert_eq!(
                p.install(|| table.msm_public(&scalars, tight)).unwrap(),
                expected,
                "threads = {threads}"
            );
            assert_eq!(
                p.install(|| table.msm_secret(&scalars, tight)).unwrap(),
                expected
            );
            assert!(matches!(
                p.install(|| table.msm_public(&scalars, short)),
                Err(MsmError::Budget(_))
            ));
        }
        assert_eq!(table.msm_tasks(7, MemoryBudget::DEFAULT), Ok(3));
        let two = MemoryBudget::new(digits + 2 * buckets);
        assert_eq!(table.msm_tasks(7, two), Ok(2));
    }
}
