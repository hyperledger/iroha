//! The signed-digit, batch-affine Pippenger engine.
//!
//! # Algorithm
//!
//! Scalars are recoded once into signed base-`2^c` digits in
//! `[-2^(c-1), 2^(c-1)]`, so each window needs only `2^(c-1)` buckets and a
//! negative digit adds the negated base. Buckets are affine; a point is added
//! to its bucket through a queue that is flushed in batches of up to 1024
//! additions sharing one field inversion. A bucket already queued in the
//! current batch receives further points in a projective overflow
//! accumulator, so adversarial inputs (every scalar equal, repeated bases)
//! never serialise the batch. Equal-point and opposite-point additions inside
//! a batch are detected and handled as doublings and cancellations.
//!
//! Each window's buckets are reduced by summation by parts, and the windows are
//! combined with `c` doublings each (Horner).
//!
//! # Determinism
//!
//! The result is a group element computed with exact arithmetic; how the work
//! is split across tasks only changes the order of exact additions, so the
//! output is identical at every thread count.
//!
//! # Timing posture
//!
//! In secret mode the shared inversion is the constant-time Fermat inversion,
//! and the digit buffers and every bucket buffer that encodes digit
//! information (coordinates, overflow accumulators, occupancy and batch marks,
//! queued bucket indices, points and signs, addition kinds and the batch
//! inversion scratch, including spare capacity) are zeroised when they are
//! dropped, also during unwinding. Bucket indices, zero-digit skipping,
//! conflict handling, empty-gap weighting and equal/opposite-point
//! checks depend on the scalar digits, which is the posture of the vendored
//! `halo2curves` MSM it replaces: it is not a constant-time MSM.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

use ff::Field;
use zeroize::Zeroize;

use crate::curve::{PastaAffine, PastaCurve};
use crate::field::PastaField;
use crate::{CancellationToken, Cancelled};
use zeroize::Zeroizing;

#[cfg(test)]
#[path = "reduction_tests.rs"]
mod reduction_tests;

#[cfg(test)]
#[path = "gap_tests.rs"]
mod gap_tests;

#[cfg(test)]
#[path = "batch_cap_experiment.rs"]
mod batch_cap_experiment;

/// Largest supported window: digits must fit `i16` with magnitude `2^(c-1)`.
pub(crate) const MAX_WINDOW: usize = 15;
/// Smallest window considered by the planner.
pub(crate) const MIN_WINDOW: usize = 2;
/// Scratch bytes per bucket: affine point, projective overflow, flags.
pub(crate) const BUCKET_BYTES: usize = 64 + 96 + 1 + 1 + 4;
/// Largest number of additions sharing one inversion.
const MAX_BATCH: usize = 1024;

/// Heap storage of a bucket set, including the bounded addition queue and
/// batch-inversion buffers. Pasta projective points occupy 96 bytes.
pub(crate) fn bucket_bytes(count: usize) -> Option<usize> {
    let cap = (count / 4).clamp(16, MAX_BATCH);
    let queued =
        cap.checked_mul(2 * size_of::<u32>() + size_of::<bool>() + size_of::<Kind>() + 2 * 32)?;
    count.checked_mul(BUCKET_BYTES)?.checked_add(queued)
}

/// Scratch retained across waves: recoded digits, skip flags and window sums.
fn fixed_bytes(n: usize, nw: usize) -> Option<usize> {
    n.checked_mul(nw)?
        .checked_mul(2)?
        .checked_add(n)?
        .checked_add(nw.checked_mul(96)?)
}

/// One live task's buckets, returned window sums and its slot in the wave.
fn task_bytes(windows: usize, buckets_per_window: usize) -> Option<usize> {
    bucket_bytes(windows.checked_mul(buckets_per_window)?)?
        .checked_add(windows.checked_mul(96)?)?
        .checked_add(size_of::<(usize, Vec<crate::Ep>)>())
}

/// Number of windows for scalars of at most `bits` bits with window `c`.
///
/// One more window than `ceil(bits / c)` may be needed for the signed-digit
/// carry; `bits / c + 1` leaves the top window at most `c - 1` real bits, so
/// its digit plus carry stays within `2^(c-1)`.
pub(crate) const fn num_windows(bits: usize, c: usize) -> usize {
    bits / c + 1
}

/// Reads `c` bits starting at bit `start` of a 256-bit little-endian value.
#[inline]
fn window_bits(limbs: &[u64; 4], start: usize, c: usize) -> u64 {
    if start >= 256 {
        return 0;
    }
    let idx = start / 64;
    let off = start % 64;
    let mut v = limbs[idx] >> off;
    if off + c > 64 && idx + 1 < 4 {
        v |= limbs[idx + 1] << (64 - off);
    }
    v & ((1u64 << c) - 1)
}

/// Branch-free signed recoding of one scalar into `out` (`nw` digits).
///
/// Digit `w` is in `[-2^(c-1), 2^(c-1)]` and
/// `sum_w out[w] * 2^(c w) = scalar`. The control flow and memory accesses do
/// not depend on the scalar.
#[inline]
pub(crate) fn recode_into(limbs: &[u64; 4], c: usize, out: &mut [i16]) {
    let half = 1i32 << (c - 1);
    let mut carry = 0i32;
    for (w, slot) in out.iter_mut().enumerate() {
        let v = window_bits(limbs, w * c, c) as i32 + carry;
        // over = 1 exactly when v > half.
        let over = ((half - v) >> 31) & 1;
        let d = v - (over << c);
        carry = over;
        *slot = d as i16;
    }
}

/// Recoded digits of a batch of scalars, zeroised on drop.
pub(crate) struct Digits {
    /// Digits in layout `[i * nw + w]`.
    pub(crate) data: Vec<i16>,
    /// Windows per scalar.
    pub(crate) nw: usize,
}

impl Drop for Digits {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

impl Digits {
    /// Recodes `scalars` in parallel on the caller's pool.
    #[cfg(test)]
    pub(crate) fn new<F: PastaField>(scalars: &[F], c: usize, nw: usize) -> Self {
        Self::new_cancellable(scalars, c, nw, None).expect("no cancellation signal")
    }

    pub(crate) fn new_cancellable<F: PastaField>(
        scalars: &[F],
        c: usize,
        nw: usize,
        cancellation: Option<&CancellationToken>,
    ) -> Result<Self, Cancelled> {
        use rayon::prelude::*;
        CancellationToken::checkpoint(cancellation)?;
        let mut data = vec![0i16; scalars.len() * nw];
        data.par_chunks_mut(nw * 1024)
            .zip(scalars.par_chunks(1024))
            .for_each(|(out, chunk)| {
                if CancellationToken::checkpoint(cancellation).is_err() {
                    return;
                }
                for (s, o) in chunk.iter().zip(out.chunks_exact_mut(nw)) {
                    let mut limbs = s.to_canonical_limbs();
                    recode_into(&limbs, c, o);
                    limbs.zeroize();
                }
            });
        let result = Self { data, nw };
        CancellationToken::checkpoint(cancellation)?;
        Ok(result)
    }

    /// The digits of scalar `i`.
    #[inline]
    pub(crate) fn row(&self, i: usize) -> &[i16] {
        &self.data[i * self.nw..(i + 1) * self.nw]
    }
}

/// Batch-affine addition kinds decided at flush time.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Kind {
    /// A general addition (the zeroised state).
    #[default]
    Add,
    /// The queued point equals the bucket: a doubling.
    Double,
    /// The queued point is the negated bucket: the bucket empties.
    Cancel,
}

impl zeroize::DefaultIsZeroes for Kind {}

/// A set of affine buckets with queued batch-affine additions.
pub(crate) struct Buckets<'a, C: PastaCurve, const SECRET: bool> {
    bases: &'a [C::AffineExt],
    x: Vec<C::Base>,
    y: Vec<C::Base>,
    has: Vec<bool>,
    mark: Vec<u32>,
    epoch: u32,
    overflow: Vec<C>,
    overflow_used: Vec<bool>,
    cap: usize,
    queue_bucket: Vec<u32>,
    queue_point: Vec<u32>,
    queue_neg: Vec<bool>,
    kind: Vec<Kind>,
    den: Vec<C::Base>,
    prefix: Vec<C::Base>,
}

impl<'a, C: PastaCurve, const SECRET: bool> Buckets<'a, C, SECRET> {
    /// Creates `count` empty buckets over the given base points.
    pub(crate) fn new(bases: &'a [C::AffineExt], count: usize) -> Self {
        let cap = (count / 4).clamp(16, MAX_BATCH);
        // Diagnostic-only smaller batches retain the production planner's
        // conservative reservation. Release libraries have no override or knob.
        #[cfg(test)]
        let cap = batch_cap_experiment::cap(count, cap);
        Self {
            bases,
            x: vec![C::Base::ZERO; count],
            y: vec![C::Base::ZERO; count],
            has: vec![false; count],
            mark: vec![0; count],
            epoch: 1,
            overflow: vec![C::identity(); count],
            overflow_used: vec![false; count],
            cap,
            queue_bucket: Vec::with_capacity(cap),
            queue_point: Vec::with_capacity(cap),
            queue_neg: Vec::with_capacity(cap),
            kind: vec![Kind::Add; cap],
            den: vec![C::Base::ZERO; cap],
            prefix: vec![C::Base::ZERO; cap],
        }
    }

    /// Adds `(-1)^neg * bases[p]` to bucket `b`. The base must not be the
    /// identity.
    #[inline]
    pub(crate) fn insert(&mut self, b: usize, p: usize, neg: bool) {
        let base = &self.bases[p];
        if !self.has[b] {
            self.x[b] = base.x();
            self.y[b] = if neg { -base.y() } else { base.y() };
            self.has[b] = true;
            return;
        }
        if self.mark[b] == self.epoch {
            // Already queued in this batch: accumulate projectively.
            let signed = if neg { -*base } else { *base };
            self.overflow[b] = self.overflow[b].add_mixed_public(&signed);
            self.overflow_used[b] = true;
            return;
        }
        self.mark[b] = self.epoch;
        // Indices fit u32: callers bound bucket and point counts by u32::MAX.
        self.queue_bucket.push(b as u32);
        self.queue_point.push(p as u32);
        self.queue_neg.push(neg);
        if self.queue_bucket.len() == self.cap {
            self.flush();
        }
    }

    /// Applies every queued addition with one shared inversion.
    pub(crate) fn flush(&mut self) {
        let m = self.queue_bucket.len();
        if m == 0 {
            return;
        }
        let mut acc = C::Base::ONE;
        for k in 0..m {
            let b = self.queue_bucket[k] as usize;
            let base = &self.bases[self.queue_point[k] as usize];
            let px = base.x();
            let py = if self.queue_neg[k] {
                -base.y()
            } else {
                base.y()
            };
            let mut d = px - self.x[b];
            if d.is_zero_vartime() {
                if py == self.y[b] {
                    d = self.y[b].double();
                    self.kind[k] = Kind::Double;
                } else {
                    d = C::Base::ONE;
                    self.kind[k] = Kind::Cancel;
                }
            } else {
                self.kind[k] = Kind::Add;
            }
            self.den[k] = d;
            self.prefix[k] = acc;
            acc *= d;
        }
        // Every denominator is nonzero, so `acc` is invertible.
        let mut inv = if SECRET {
            acc.invert().unwrap_or(C::Base::ZERO)
        } else {
            acc.invert_vartime().unwrap_or(C::Base::ZERO)
        };
        for k in (0..m).rev() {
            let dinv = inv * self.prefix[k];
            inv *= self.den[k];
            let b = self.queue_bucket[k] as usize;
            let base = &self.bases[self.queue_point[k] as usize];
            match self.kind[k] {
                Kind::Cancel => self.has[b] = false,
                Kind::Add => {
                    let x2 = base.x();
                    let y2 = if self.queue_neg[k] {
                        -base.y()
                    } else {
                        base.y()
                    };
                    let (x1, y1) = (self.x[b], self.y[b]);
                    let lambda = (y2 - y1) * dinv;
                    let x3 = lambda.square() - x1 - x2;
                    self.y[b] = lambda * (x1 - x3) - y1;
                    self.x[b] = x3;
                }
                Kind::Double => {
                    let (x1, y1) = (self.x[b], self.y[b]);
                    let xx = x1.square();
                    let lambda = (xx.double() + xx) * dinv;
                    let x3 = lambda.square() - x1.double();
                    self.y[b] = lambda * (x1 - x3) - y1;
                    self.x[b] = x3;
                }
            }
        }
        self.queue_bucket.clear();
        self.queue_point.clear();
        self.queue_neg.clear();
        if self.epoch == u32::MAX {
            self.mark.iter_mut().for_each(|m| *m = 0);
            self.epoch = 1;
        } else {
            self.epoch += 1;
        }
    }

    /// Returns `sum_j (j + 1) * B_j` over buckets `[start, start + len)`.
    pub(crate) fn reduce(&self, start: usize, len: usize) -> C {
        let mut running = C::identity();
        let mut acc = C::identity();
        // Occupancy is digit-dependent under the existing variable-time
        // MSM contract. An empty gap repeats the same running sum; multiply
        // it by that exact positive gap length with complete curve formulas.
        // Dense windows keep their one-addition path. No scratch is added.
        let occupied = |j: usize| self.has[j] || self.overflow_used[j];
        let Some(last) = (start..start + len).rfind(|&j| occupied(j)) else {
            return acc;
        };
        // Retain the original reduction for dense windows. Counting stops
        // once one occupied bucket per 32 positions is established; this
        // avoids imposing gap-multiply overhead on coefficient-form MSMs.
        let cutoff = (last - start + 1).div_ceil(32);
        if (start..=last).filter(|&j| occupied(j)).take(cutoff).count() == cutoff {
            for j in (start..=last).rev() {
                if self.has[j] {
                    running = running.add_affine_coords(self.x[j], self.y[j]);
                }
                if self.overflow_used[j] {
                    running += self.overflow[j];
                }
                acc += running;
            }
            return acc;
        }
        let mut occupied = (start..=last)
            .rev()
            .filter(|&j| self.has[j] || self.overflow_used[j])
            .peekable();
        while let Some(j) = occupied.next() {
            if self.has[j] {
                running = running.add_affine_coords(self.x[j], self.y[j]);
            }
            if self.overflow_used[j] {
                running += self.overflow[j];
            }
            let gap = occupied.peek().map_or(j - start + 1, |&next| j - next);
            if gap == 1 {
                acc += running;
            } else {
                acc += multiply_gap_vartime(running, gap);
            }
        }
        acc
    }

    /// Zeroes, in secret mode, every buffer that may encode secret digit
    /// information. Runs on drop (including unwinding); the buckets stay
    /// usable and empty afterwards.
    pub(crate) fn wipe(&mut self) {
        if SECRET {
            self.x.iter_mut().zeroize();
            self.y.iter_mut().zeroize();
            self.has.iter_mut().zeroize();
            self.mark.iter_mut().zeroize();
            self.epoch = 1;
            self.overflow.iter_mut().zeroize();
            self.overflow_used.iter_mut().zeroize();
            // The queues are empty after a flush; `Vec::zeroize` also clears
            // entries left by an unwind and zeroes the spare capacity.
            self.queue_bucket.zeroize();
            self.queue_point.zeroize();
            self.queue_neg.zeroize();
            self.kind.iter_mut().zeroize();
            self.den.iter_mut().zeroize();
            self.prefix.iter_mut().zeroize();
        }
    }
}

impl<C: PastaCurve, const SECRET: bool> Drop for Buckets<'_, C, SECRET> {
    fn drop(&mut self) {
        self.wipe();
    }
}

/// The exact repeated sum of a running bucket total across an empty gap.
/// The gap depends on digit occupancy; this is part of the variable-time
/// prover MSM, never a replacement for a constant-time scalar multiplier.
fn multiply_gap_vartime<C: PastaCurve>(point: C, gap: usize) -> C {
    if gap == 0 {
        return C::identity();
    }
    let mut result = point;
    let top = usize::BITS - 1 - gap.leading_zeros();
    for bit in (0..top).rev() {
        result = result.double();
        if (gap >> bit) & 1 == 1 {
            result += point;
        }
    }
    result
}

/// Mixed addition helpers on projective points used by the engine.
pub(crate) trait EngineOps: PastaCurve {
    /// `self + p` for an affine point `p` (complete).
    fn add_mixed_public(&self, p: &Self::AffineExt) -> Self;
    /// `self + (x, y)` for a non-identity affine point (complete).
    fn add_affine_coords(&self, x: Self::Base, y: Self::Base) -> Self;
}

impl<C: PastaCurve> EngineOps for C {
    #[inline]
    fn add_mixed_public(&self, p: &Self::AffineExt) -> Self {
        *self + *p
    }

    #[inline]
    fn add_affine_coords(&self, x: Self::Base, y: Self::Base) -> Self {
        *self + crate::curve::affine_unchecked::<C::AffineExt>(x, y)
    }
}

/// Window plan for one MSM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Plan {
    /// Window width.
    pub(crate) c: usize,
    /// Number of windows.
    pub(crate) nw: usize,
    /// Number of window groups (tasks along the window axis).
    pub(crate) groups: usize,
    /// Windows per group.
    pub(crate) per_group: usize,
    /// Number of point chunks (tasks along the point axis).
    pub(crate) chunks: usize,
    /// Tasks allowed to hold buckets at the same time.
    pub(crate) concurrency: usize,
    /// Scratch bytes the plan holds at peak.
    pub(crate) bytes: usize,
}

/// Cost of the variable-base MSM with window `c` in multiplication units:
/// `nw * (n * 6 + 2^(c-1) * 25)` (a batch-affine bucket addition costs about
/// six multiplications; reducing one bucket about 25).
fn model_cost(n: usize, bits: usize, c: usize) -> u128 {
    let nw = num_windows(bits, c) as u128;
    let n = n as u128;
    nw * (n * 6 + (1u128 << (c - 1)) * 25)
}

/// Picks the window and task split for `n` scalars of at most `bits` bits on
/// `threads` workers within `budget` bytes.
///
/// For every window width the planner first splits windows across the
/// workers (keeping one task's buckets near the L2 size), then lowers the
/// number of concurrently live tasks until the bucket and digit scratch fits
/// the budget. Among feasible widths it minimises the modelled cost divided by
/// the achieved concurrency.
pub(crate) fn plan(n: usize, bits: usize, threads: usize, budget: usize) -> Option<Plan> {
    let threads = threads.max(1);
    let mut best: Option<(u128, Plan)> = None;
    for c in MIN_WINDOW..=MAX_WINDOW {
        let nw = num_windows(bits, c);
        let nb_per = 1usize << (c - 1);
        let fixed = fixed_bytes(n, nw)?;
        let Some(avail) = budget.checked_sub(fixed) else {
            continue;
        };
        let max_windows_per_task = ((2usize << 20) / (nb_per * BUCKET_BYTES)).max(1);
        let mut per_group = nw
            .div_ceil(threads.min(nw))
            .min(max_windows_per_task)
            .max(1);
        // Shrink tasks to one window if a single task would not fit.
        while per_group > 1 && task_bytes(per_group, nb_per)? > avail {
            per_group = per_group.div_ceil(2);
        }
        let task_bytes = task_bytes(per_group, nb_per)?;
        if task_bytes > avail {
            continue;
        }
        let groups = nw.div_ceil(per_group);
        let chunks = if threads > groups && n >= 8192 {
            threads.div_ceil(groups)
        } else {
            1
        };
        let concurrency = (groups * chunks)
            .min(threads)
            .min(avail / task_bytes)
            .max(1);
        let bytes = concurrency * task_bytes + fixed;
        let cost = model_cost(n, bits, c) / (concurrency as u128);
        if best.is_none_or(|(b, _)| cost < b) {
            best = Some((
                cost,
                Plan {
                    c,
                    nw,
                    groups,
                    per_group,
                    chunks,
                    concurrency,
                    bytes,
                },
            ));
        }
    }
    best.map(|(_, p)| p)
}

/// The smallest budget [`plan`] accepts: over every window width, the digits
/// of all windows, skip flags and window sums, plus one task holding a single
/// window's buckets and result, exactly the feasibility test of [`plan`].
pub(crate) fn min_plan_bytes(n: usize, bits: usize) -> usize {
    (MIN_WINDOW..=MAX_WINDOW)
        .filter_map(|c| {
            fixed_bytes(n, num_windows(bits, c))?.checked_add(task_bytes(1, 1usize << (c - 1))?)
        })
        .min()
        .unwrap_or(usize::MAX)
}

/// Runs the bucket phase of one task and returns its per-window sums.
#[cfg(test)]
pub(crate) fn run_task<C: PastaCurve, const SECRET: bool>(
    bases: &[C::AffineExt],
    skip: &[bool],
    digits: &Digits,
    plan: &Plan,
    group: usize,
    chunk: usize,
) -> (usize, Vec<C>) {
    let (start, sums) =
        run_task_cancellable::<C, SECRET>(bases, skip, digits, plan, group, chunk, None);
    (start, sums.to_vec())
}

pub(crate) fn run_task_cancellable<C: PastaCurve, const SECRET: bool>(
    bases: &[C::AffineExt],
    skip: &[bool],
    digits: &Digits,
    plan: &Plan,
    group: usize,
    chunk: usize,
    cancellation: Option<&CancellationToken>,
) -> (usize, Zeroizing<Vec<C>>) {
    let w0 = group * plan.per_group;
    let w1 = ((group + 1) * plan.per_group).min(plan.nw);
    if w0 >= w1 || CancellationToken::checkpoint(cancellation).is_err() {
        return (w0, Zeroizing::new(Vec::new()));
    }
    let n = bases.len();
    let nb_per = 1usize << (plan.c - 1);
    let windows = w1 - w0;
    let mut buckets = Buckets::<C, SECRET>::new(bases, windows * nb_per);
    let step = n.div_ceil(plan.chunks);
    let i0 = chunk * step;
    let i1 = ((chunk + 1) * step).min(n);
    for (i, _) in skip.iter().enumerate().take(i1).skip(i0) {
        if i % 256 == 0 && CancellationToken::checkpoint(cancellation).is_err() {
            return (w0, Zeroizing::new(Vec::new()));
        }
        if skip[i] {
            continue;
        }
        let row = &digits.row(i)[w0..w1];
        for (gw, &d) in row.iter().enumerate() {
            if d != 0 {
                let b = gw * nb_per + (usize::from(d.unsigned_abs()) - 1);
                buckets.insert(b, i, d < 0);
            }
        }
    }
    buckets.flush();
    let sums = (0..windows)
        .map(|gw| buckets.reduce(gw * nb_per, nb_per))
        .collect();
    // Dropping `buckets` wipes its scratch in secret mode.
    (w0, Zeroizing::new(sums))
}

/// Combines per-window sums: `sum_w 2^(c w) * W_w`.
pub(crate) fn combine<C: PastaCurve>(windows: &[C], c: usize) -> C {
    let mut acc = C::identity();
    for w in windows.iter().rev() {
        for _ in 0..c {
            acc = acc.double();
        }
        acc += w;
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::{Ep, EpAffine};
    use crate::field::Fq;
    use ff::PrimeField;
    use group::{Curve, Group};

    #[test]
    fn recoding_reconstructs_scalars() {
        for c in [2usize, 3, 7, 8, 13, 15] {
            let nw = num_windows(255, c);
            for v in [
                Fq::ZERO,
                Fq::ONE,
                -Fq::ONE,
                Fq::from(0xdead_beefu64),
                Fq::TWO_INV,
                Fq::from_u128(u128::MAX),
            ] {
                let mut digits = vec![0i16; nw];
                recode_into(&v.to_canonical_limbs(), c, &mut digits);
                let mut acc = Fq::ZERO;
                let base = Fq::from(1u64 << c);
                for d in digits.iter().rev() {
                    acc *= base;
                    let mag = Fq::from(u64::from(d.unsigned_abs()));
                    acc += if *d < 0 { -mag } else { mag };
                    assert!(i32::from(d.unsigned_abs()) <= 1 << (c - 1));
                }
                assert_eq!(acc, v, "c = {c}");
            }
        }
        assert_eq!(window_bits(&[u64::MAX, 1, 0, 0], 60, 8), 0x1F);
        assert_eq!(window_bits(&[0; 4], 300, 8), 0);
    }

    #[test]
    fn planner_respects_budget() {
        let p = plan(1 << 16, 255, 4, usize::MAX).unwrap();
        assert!((10..=14).contains(&p.c), "{p:?}");
        assert!(p.groups * p.per_group >= p.nw);
        let tight = plan(1 << 16, 255, 4, 4 << 20).unwrap();
        assert!(tight.bytes <= 4 << 20, "{tight:?}");
        assert!(tight.concurrency >= 1);
        let one = plan(1 << 16, 255, 1, usize::MAX).unwrap();
        assert_eq!(one.concurrency, 1);
        assert!(plan(1 << 16, 255, 4, 1000).is_none());
        assert!(min_plan_bytes(1 << 16, 255) > 1000);
        assert_eq!(min_plan_bytes(usize::MAX, 255), usize::MAX);
        assert_eq!(num_windows(255, 15), 18);
        assert!(model_cost(1000, 255, 8) > 0);
    }

    #[test]
    fn bucket_accounting_covers_every_allocated_buffer() {
        fn bytes<T>(values: &Vec<T>) -> usize {
            values.capacity() * size_of::<T>()
        }
        for count in [2, 8, 16, 1024, 4096, 1 << 15] {
            let buckets = Buckets::<Ep, false>::new(&[], count);
            let allocated = bytes(&buckets.x)
                + bytes(&buckets.y)
                + bytes(&buckets.has)
                + bytes(&buckets.mark)
                + bytes(&buckets.overflow)
                + bytes(&buckets.overflow_used)
                + bytes(&buckets.queue_bucket)
                + bytes(&buckets.queue_point)
                + bytes(&buckets.queue_neg)
                + bytes(&buckets.kind)
                + bytes(&buckets.den)
                + bytes(&buckets.prefix);
            assert_eq!(bucket_bytes(count), Some(allocated));
        }
        assert_eq!(size_of::<crate::Ep>(), 96);
        assert_eq!(size_of::<crate::Eq>(), 96);
        assert_eq!(size_of::<crate::Fp>(), 32);
        assert_eq!(size_of::<crate::Fq>(), 32);
        assert!(bucket_bytes(usize::MAX).is_none());
    }

    #[test]
    fn min_plan_bytes_is_the_exact_feasibility_boundary() {
        for (n, bits) in [
            (4096usize, 255usize),
            (9, 255),
            (100_000, 64),
            (1 << 16, 255),
        ] {
            let min = min_plan_bytes(n, bits);
            for threads in [1usize, 4, 7] {
                let p = plan(n, bits, threads, min).expect("the minimum is feasible");
                assert!(p.bytes <= min, "n = {n} bits = {bits}: {p:?}");
                assert!(
                    plan(n, bits, threads, min - 1).is_none(),
                    "n = {n} bits = {bits}"
                );
            }
        }
        // The old c = 2 all-windows figure overstated n = 4096 about fourfold.
        let old = 4096 * num_windows(255, 2) * 2 + num_windows(255, 2) * 2 * BUCKET_BYTES;
        assert!(min_plan_bytes(4096, 255) * 3 < old);
    }

    #[test]
    fn secret_wipe_clears_every_digit_dependent_buffer() {
        let g = Ep::generator().to_affine();
        let bases = vec![g, Ep::generator().double().to_affine(), -g];
        let mut s = Buckets::<Ep, true>::new(&bases, 8);
        s.insert(1, 0, false);
        s.insert(1, 1, true);
        s.insert(1, 2, false);
        s.insert(5, 2, true);
        s.insert(5, 0, false);
        s.flush();
        // Leave an unflushed queue entry, as an unwind would.
        s.insert(6, 0, false);
        s.insert(6, 1, false);
        assert!(!s.queue_bucket.is_empty());
        s.wipe();
        assert!(s.x.iter().chain(&s.y).all(|v| bool::from(v.is_zero())));
        assert!(s.has.iter().chain(&s.overflow_used).all(|h| !h));
        assert!(s.mark.iter().all(|m| *m == 0));
        assert_eq!(s.epoch, 1);
        assert!(s.overflow.iter().all(|p| bool::from(p.is_identity())));
        assert!(s.queue_bucket.is_empty() && s.queue_point.is_empty() && s.queue_neg.is_empty());
        assert!(s.kind.iter().all(|k| *k == Kind::Add));
        assert!(
            s.den
                .iter()
                .chain(&s.prefix)
                .all(|v| bool::from(v.is_zero()))
        );
        // The wiped buckets are empty and still usable.
        assert_eq!(s.reduce(0, 8), Ep::identity());
        s.insert(0, 0, false);
        s.flush();
        assert_eq!(s.reduce(0, 1), Ep::generator());
        // Public mode keeps its buffers (nothing secret to clear).
        let mut p = Buckets::<Ep, false>::new(&bases, 2);
        p.insert(0, 0, false);
        p.wipe();
        assert!(p.has[0]);
    }

    #[test]
    fn buckets_handle_double_cancel_and_overflow() {
        let g = Ep::generator().to_affine();
        let bases = vec![g, g, -g, g];
        let mut b = Buckets::<Ep, false>::new(&bases, 4);
        // bucket 0: g + g (double) ; bucket 1: g - g (cancel) ; bucket 2: g + g + g via overflow
        b.insert(0, 0, false);
        b.insert(0, 1, false);
        b.insert(1, 0, false);
        b.insert(1, 2, false);
        b.insert(2, 0, false);
        b.insert(2, 1, false);
        b.insert(2, 3, false);
        b.flush();
        let gp = Ep::generator();
        assert_eq!(b.reduce(0, 1), gp.double());
        assert_eq!(b.reduce(1, 1), Ep::identity());
        assert_eq!(b.reduce(2, 1), gp + gp + gp);
        let mut s = Buckets::<Ep, true>::new(&bases, 4);
        s.insert(3, 0, true);
        s.flush();
        assert_eq!(s.reduce(3, 1), -gp);
        s.wipe();
        let windows = [gp, gp];
        assert_eq!(combine(&windows, 2), gp * Fq::from(5u64));
        let _: EpAffine = EpAffine::default();
    }
}
