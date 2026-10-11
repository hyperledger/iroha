//! Number-theoretic transforms over the Pasta fields.
//!
//! [`FftDomain`] evaluates and interpolates polynomials on the multiplicative
//! subgroup of order `n = 2^k`, and on its cosets. It uses the generator
//! halo2 uses: `omega = ROOT_OF_UNITY^(2^(32 - k))`.
//!
//! # Algorithm
//!
//! Decimation in frequency (natural-order input, bit-reversed intermediate
//! order), iterative, with two radix-2 stages fused per pass ("radix-4"
//! memory traffic: each pass reads and writes the array once for two stages).
//! A trailing radix-2 stage runs when `k` is odd. The final pass restores
//! natural order. In a prime field a radix-4 butterfly needs the same number of
//! multiplications as two radix-2 stages, so the gain is memory traffic only.
//!
//! The twiddle factors of every stage are cached contiguously in the domain
//! ([`FftDomain::twiddle_bytes`] reports their size). The coset shift is fused
//! into the first pass of [`FftDomain::coset_fft`]; the inverse transforms fuse
//! the `1/n` scaling (and the inverse shift) into the final reordering pass.
//!
//! # Determinism
//!
//! The transforms are exact field arithmetic, so the output is a pure function
//! of the input regardless of the Rayon pool size or chunking.
#![allow(clippy::many_single_char_names)]

use rayon::prelude::*;

use crate::field::PastaField;
use crate::{CancellationToken, Cancelled};

/// Below this many elements per pass the transforms run on the calling
/// thread; above it they split work across the caller's Rayon pool.
const PARALLEL_MIN: usize = 1 << 12;

/// FFT domain construction failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FftError {
    /// The caller cancelled this transform; its in-place buffer is incomplete.
    Cancelled,
    /// `k` exceeds the 2-adicity of the field (32) or the platform limit.
    UnsupportedSize {
        /// The requested `log2(n)`.
        k: u64,
    },
    /// The input length is not `n`.
    WrongLength {
        /// The domain size `n`.
        expected: usize,
        /// The input length.
        actual: usize,
    },
    /// The source and destination batches have different column counts.
    WrongColumnCount {
        /// The number of destination columns.
        expected: usize,
        /// The number of source columns.
        actual: usize,
    },
    /// A coset shift of zero (not a coset; the inverse transform would need
    /// `0^-1`).
    ZeroShift,
}

impl core::fmt::Display for FftError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Cancelled => f.write_str("FFT: operation cancelled"),
            Self::UnsupportedSize { k } => write!(f, "unsupported FFT size 2^{k}"),
            Self::WrongLength { expected, actual } => {
                write!(f, "FFT input has {actual} elements, expected {expected}")
            }
            Self::WrongColumnCount { expected, actual } => {
                write!(f, "FFT has {actual} source columns, expected {expected}")
            }
            Self::ZeroShift => write!(f, "FFT coset shift is zero"),
        }
    }
}

impl std::error::Error for FftError {}
impl From<Cancelled> for FftError {
    fn from(_: Cancelled) -> Self {
        Self::Cancelled
    }
}

/// A multiplicative subgroup of order `2^k` with cached twiddle factors.
#[derive(Clone, Debug)]
pub struct FftDomain<F: PastaField> {
    k: u32,
    n: usize,
    omega: F,
    omega_inv: F,
    n_inv: F,
    /// `forward[s]` holds `w_{2h}^j` for `j < h`, `h = 2^s`.
    forward: Vec<Vec<F>>,
    /// The same for `omega_inv`.
    inverse: Vec<Vec<F>>,
}

/// A validated coset transform plan borrowing the exact domain and caller powers.
#[derive(Clone, Copy, Debug)]
pub struct CosetFftPlan<'domain, 'scratch, F: PastaField> {
    domain: &'domain FftDomain<F>,
    powers: &'scratch [F],
}

impl<F: PastaField> CosetFftPlan<'_, '_, F> {
    /// Evaluates columns in place using the immutable validated powers.
    ///
    /// # Errors
    ///
    /// Rejects any wrong column length before mutating any input.
    pub fn fft_many(&self, columns: &mut [&mut [F]]) -> Result<(), FftError> {
        self.fft_many_cancellable(columns, None)
    }

    /// Runs [`Self::fft_many`] with an explicit per-operation cancellation signal.
    /// All Rayon tasks join before returning. After cancellation the buffer is
    /// incomplete and must be discarded or reinitialized by its owner.
    ///
    /// # Errors
    /// As [`Self::fft_many`], or [`FftError::Cancelled`].
    pub fn fft_many_cancellable(
        &self,
        columns: &mut [&mut [F]],
        cancellation: Option<&CancellationToken>,
    ) -> Result<(), FftError> {
        CancellationToken::checkpoint(cancellation)?;
        for column in columns.iter() {
            self.domain.check(column)?;
        }
        let shift = Some(CosetShift::Prepared(self.powers));
        if let [column] = columns {
            dif::<_, true>(column, &self.domain.forward, shift, cancellation);
            bit_reverse_scale::<_, true>(column, self.domain.k, None, cancellation);
        } else {
            columns.par_iter_mut().for_each(|column| {
                dif::<_, false>(column, &self.domain.forward, shift, cancellation);
                bit_reverse_scale::<_, false>(column, self.domain.k, None, cancellation);
            });
        }
        CancellationToken::checkpoint(cancellation)?;
        Ok(())
    }

    /// Evaluates immutable coefficient columns into caller-owned output columns.
    ///
    /// The first butterfly pass reads the coefficients directly, avoiding a
    /// separate copy into the output. Later passes reuse that output in place.
    /// Each source is borrowed exactly once and retained as slice metadata before
    /// validation. Powers and coefficients remain unchanged; no field scratch
    /// is allocated.
    /// All Rayon tasks join before cancellation is reported. A cancelled output
    /// is incomplete and must be discarded or reinitialized by its owner.
    ///
    /// # Errors
    ///
    /// Checks cancellation, then column count, then every source/destination
    /// length before writing any output. A mismatch returns
    /// [`FftError::WrongColumnCount`] or [`FftError::WrongLength`].
    pub fn fft_many_from_cancellable(
        &self,
        coefficients: &[impl AsRef<[F]> + Sync],
        columns: &mut [&mut [F]],
        cancellation: Option<&CancellationToken>,
    ) -> Result<(), FftError> {
        CancellationToken::checkpoint(cancellation)?;
        if coefficients.len() != columns.len() {
            return Err(FftError::WrongColumnCount {
                expected: columns.len(),
                actual: coefficients.len(),
            });
        }
        // AsRef need not return the same slice on a later call. Freeze its first
        // result so the exact views checked below also supply the butterflies.
        let sources: Vec<&[F]> = coefficients.iter().map(AsRef::as_ref).collect();
        for (source, output) in sources.iter().zip(columns.iter()) {
            self.domain.check(source)?;
            self.domain.check(output)?;
        }
        CancellationToken::checkpoint(cancellation)?;
        if let [column] = columns {
            dif_from::<_, true>(
                sources[0],
                column,
                &self.domain.forward,
                self.powers,
                cancellation,
            );
            bit_reverse_scale::<_, true>(column, self.domain.k, None, cancellation);
        } else {
            columns
                .par_iter_mut()
                .zip(sources.par_iter())
                .for_each(|(column, source)| {
                    dif_from::<_, false>(
                        source,
                        column,
                        &self.domain.forward,
                        self.powers,
                        cancellation,
                    );
                    bit_reverse_scale::<_, false>(column, self.domain.k, None, cancellation);
                });
        }
        CancellationToken::checkpoint(cancellation)?;
        Ok(())
    }
}

/// Exact first-pass coset scaling; all later passes have no shift.
#[derive(Clone, Copy)]
enum CosetShift<'a, F> {
    Geometric(F),
    Prepared(&'a [F]),
}

impl<F: PastaField> FftDomain<F> {
    /// Builds the domain of size `2^k` and its twiddle caches.
    ///
    /// # Errors
    ///
    /// [`FftError::UnsupportedSize`] when `k > 32` or `2^k` does not fit
    /// `usize`.
    pub fn new(k: u32) -> Result<Self, FftError> {
        if k > F::S || k >= usize::BITS {
            return Err(FftError::UnsupportedSize { k: u64::from(k) });
        }
        let n = 1usize << k;
        let mut omega = F::ROOT_OF_UNITY;
        let mut omega_inv = F::ROOT_OF_UNITY_INV;
        for _ in k..F::S {
            omega = omega.square();
            omega_inv = omega_inv.square();
        }
        // n^-1 = (1/2)^k.
        let n_inv = F::TWO_INV.pow_vartime([u64::from(k)]);
        let forward = stage_twiddles(omega, k);
        let inverse = stage_twiddles(omega_inv, k);
        Ok(Self {
            k,
            n,
            omega,
            omega_inv,
            n_inv,
            forward,
            inverse,
        })
    }

    /// `log2` of the domain size.
    pub fn k(&self) -> u32 {
        self.k
    }

    /// The domain size `n = 2^k`.
    pub fn n(&self) -> usize {
        self.n
    }

    /// The generator `omega` of the subgroup.
    pub fn omega(&self) -> F {
        self.omega
    }

    /// `omega^-1`.
    pub fn omega_inv(&self) -> F {
        self.omega_inv
    }

    /// `n^-1`.
    pub fn n_inv(&self) -> F {
        self.n_inv
    }

    /// Bytes held by the twiddle caches (both directions).
    pub fn twiddle_bytes(&self) -> usize {
        let count: usize = self
            .forward
            .iter()
            .chain(self.inverse.iter())
            .map(Vec::len)
            .sum();
        count.saturating_mul(core::mem::size_of::<F>())
    }

    fn check(&self, a: &[F]) -> Result<(), FftError> {
        if a.len() == self.n {
            Ok(())
        } else {
            Err(FftError::WrongLength {
                expected: self.n,
                actual: a.len(),
            })
        }
    }

    /// Evaluates the polynomial with coefficients `a` at `omega^i`, in place.
    ///
    /// # Errors
    ///
    /// [`FftError::WrongLength`] unless `a.len() == n`.
    pub fn fft(&self, a: &mut [F]) -> Result<(), FftError> {
        self.fft_cancellable(a, None)
    }

    /// Runs [`Self::fft`] with an explicit per-operation cancellation signal.
    /// All Rayon tasks join before returning. After cancellation the buffer is
    /// incomplete and must be discarded or reinitialized by its owner.
    ///
    /// # Errors
    /// As [`Self::fft`], or [`FftError::Cancelled`].
    pub fn fft_cancellable(
        &self,
        a: &mut [F],
        cancellation: Option<&CancellationToken>,
    ) -> Result<(), FftError> {
        CancellationToken::checkpoint(cancellation)?;
        self.check(a)?;
        dif::<_, true>(a, &self.forward, None, cancellation);
        bit_reverse_scale::<_, true>(a, self.k, None, cancellation);
        CancellationToken::checkpoint(cancellation)?;
        Ok(())
    }

    /// Interpolates evaluations at `omega^i` back to coefficients, in place.
    ///
    /// # Errors
    ///
    /// [`FftError::WrongLength`] unless `a.len() == n`.
    pub fn ifft(&self, a: &mut [F]) -> Result<(), FftError> {
        self.ifft_cancellable(a, None)
    }

    /// Runs [`Self::ifft`] with an explicit per-operation cancellation signal.
    /// All Rayon tasks join before returning. After cancellation the buffer is
    /// incomplete and must be discarded or reinitialized by its owner.
    ///
    /// # Errors
    /// As [`Self::ifft`], or [`FftError::Cancelled`].
    pub fn ifft_cancellable(
        &self,
        a: &mut [F],
        cancellation: Option<&CancellationToken>,
    ) -> Result<(), FftError> {
        CancellationToken::checkpoint(cancellation)?;
        self.check(a)?;
        dif::<_, true>(a, &self.inverse, None, cancellation);
        bit_reverse_scale::<_, true>(a, self.k, Some((self.n_inv, F::ONE)), cancellation);
        CancellationToken::checkpoint(cancellation)?;
        Ok(())
    }

    /// Evaluates the polynomial with coefficients `a` at `shift * omega^i`,
    /// in place. The multiplication of coefficient `i` by `shift^i` is fused
    /// into the first pass.
    ///
    /// # Errors
    ///
    /// [`FftError::WrongLength`] unless `a.len() == n`;
    /// [`FftError::ZeroShift`] for `shift = 0`, which is not a coset (checked
    /// before `a` is touched).
    pub fn coset_fft(&self, a: &mut [F], shift: F) -> Result<(), FftError> {
        self.coset_fft_cancellable(a, shift, None)
    }

    /// Runs [`Self::coset_fft`] with an explicit per-operation cancellation signal.
    /// All Rayon tasks join before returning. After cancellation the buffer is
    /// incomplete and must be discarded or reinitialized by its owner.
    ///
    /// # Errors
    /// As [`Self::coset_fft`], or [`FftError::Cancelled`].
    pub fn coset_fft_cancellable(
        &self,
        a: &mut [F],
        shift: F,
        cancellation: Option<&CancellationToken>,
    ) -> Result<(), FftError> {
        CancellationToken::checkpoint(cancellation)?;
        self.check(a)?;
        check_shift(&shift)?;
        dif::<_, true>(
            a,
            &self.forward,
            Some(CosetShift::Geometric(shift)),
            cancellation,
        );
        bit_reverse_scale::<_, true>(a, self.k, None, cancellation);
        CancellationToken::checkpoint(cancellation)?;
        Ok(())
    }

    /// Evaluates several coefficient columns on the same coset, in place.
    ///
    /// Multiple columns run independently across the caller's Rayon pool;
    /// each uses the same butterfly arithmetic as [`Self::coset_fft`], without
    /// nested parallel passes. One column retains the single-transform
    /// scheduling. The domain's immutable twiddles are shared and no field
    /// scratch buffers are allocated. Column order and worker count cannot
    /// affect the output.
    ///
    /// # Errors
    ///
    /// [`FftError::WrongLength`] if any column's length differs from `n`, then
    /// [`FftError::ZeroShift`] for `shift = 0`. All columns and the shift are
    /// checked before any input is touched, including for an empty batch.
    pub fn coset_fft_many(&self, columns: &mut [&mut [F]], shift: F) -> Result<(), FftError> {
        self.coset_fft_many_cancellable(columns, shift, None)
    }

    /// Runs [`Self::coset_fft_many`] with an explicit per-operation cancellation signal.
    /// All Rayon tasks join before returning. After cancellation the buffer is
    /// incomplete and must be discarded or reinitialized by its owner.
    ///
    /// # Errors
    /// As [`Self::coset_fft_many`], or [`FftError::Cancelled`].
    pub fn coset_fft_many_cancellable(
        &self,
        columns: &mut [&mut [F]],
        shift: F,
        cancellation: Option<&CancellationToken>,
    ) -> Result<(), FftError> {
        CancellationToken::checkpoint(cancellation)?;
        for column in columns.iter() {
            self.check(column)?;
        }
        check_shift(&shift)?;
        if let [column] = columns {
            return self.coset_fft_cancellable(column, shift, cancellation);
        }
        columns.par_iter_mut().for_each(|column| {
            dif::<_, false>(
                column,
                &self.forward,
                Some(CosetShift::Geometric(shift)),
                cancellation,
            );
            bit_reverse_scale::<_, false>(column, self.k, None, cancellation);
        });
        CancellationToken::checkpoint(cancellation)?;
        Ok(())
    }

    /// Fills caller-owned powers and binds them immutably to this domain.
    ///
    /// The plan and its transforms allocate no field scratch. The caller must
    /// retain and account for exactly `n` field elements for the plan lifetime.
    /// Powers use the same exact arithmetic for every caller worker count.
    ///
    /// # Errors
    ///
    /// Rejects a wrong scratch length or zero shift before touching scratch.
    pub fn coset_plan<'domain, 'scratch>(
        &'domain self,
        scratch: &'scratch mut [F],
        shift: F,
    ) -> Result<CosetFftPlan<'domain, 'scratch, F>, FftError> {
        self.coset_plan_cancellable(scratch, shift, None)
    }

    /// Prepares coset powers with an explicit cancellation signal.
    ///
    /// # Errors
    /// As [`Self::coset_plan`], or [`FftError::Cancelled`]; scratch then holds
    /// incomplete powers and remains exclusively owned by the caller.
    pub fn coset_plan_cancellable<'domain, 'scratch>(
        &'domain self,
        scratch: &'scratch mut [F],
        shift: F,
        cancellation: Option<&CancellationToken>,
    ) -> Result<CosetFftPlan<'domain, 'scratch, F>, FftError> {
        CancellationToken::checkpoint(cancellation)?;
        self.check(scratch)?;
        check_shift(&shift)?;
        let fill = |(index, chunk): (usize, &mut [F])| {
            if CancellationToken::checkpoint(cancellation).is_err() {
                return;
            }
            let mut power = shift.pow_vartime([(index * PARALLEL_MIN) as u64]);
            for value in chunk {
                *value = power;
                power *= shift;
            }
        };
        if self.n >= PARALLEL_MIN {
            scratch
                .par_chunks_mut(PARALLEL_MIN)
                .enumerate()
                .for_each(fill);
        } else {
            fill((0, scratch));
        }
        CancellationToken::checkpoint(cancellation)?;
        Ok(CosetFftPlan {
            domain: self,
            powers: scratch,
        })
    }

    /// Interpolates evaluations at `shift * omega^i` back to coefficients, in
    /// place.
    ///
    /// # Errors
    ///
    /// [`FftError::WrongLength`] unless `a.len() == n`;
    /// [`FftError::ZeroShift`] for `shift = 0` (checked before `a` is
    /// touched).
    pub fn coset_ifft(&self, a: &mut [F], shift: F) -> Result<(), FftError> {
        self.coset_ifft_cancellable(a, shift, None)
    }

    /// Runs [`Self::coset_ifft`] with an explicit per-operation cancellation signal.
    /// All Rayon tasks join before returning. After cancellation the buffer is
    /// incomplete and must be discarded or reinitialized by its owner.
    ///
    /// # Errors
    /// As [`Self::coset_ifft`], or [`FftError::Cancelled`].
    pub fn coset_ifft_cancellable(
        &self,
        a: &mut [F],
        shift: F,
        cancellation: Option<&CancellationToken>,
    ) -> Result<(), FftError> {
        CancellationToken::checkpoint(cancellation)?;
        self.check(a)?;
        check_shift(&shift)?;
        // `shift` is nonzero, so the inverse exists.
        let shift_inv = shift.invert().unwrap_or(F::ZERO);
        dif::<_, true>(a, &self.inverse, None, cancellation);
        bit_reverse_scale::<_, true>(a, self.k, Some((self.n_inv, shift_inv)), cancellation);
        CancellationToken::checkpoint(cancellation)?;
        Ok(())
    }
}

/// Rejects a zero coset shift.
fn check_shift<F: PastaField>(shift: &F) -> Result<(), FftError> {
    if bool::from(shift.is_zero()) {
        Err(FftError::ZeroShift)
    } else {
        Ok(())
    }
}

/// `tw[s][j] = w^j` with `w` the primitive `2^(s+1)`-th root, for `j < 2^s`.
fn stage_twiddles<F: PastaField>(omega: F, k: u32) -> Vec<Vec<F>> {
    (0..k)
        .map(|s| {
            // w_{2h} = omega^(n / 2h) = omega^(2^(k - s - 1)).
            let w = omega.pow_vartime([1u64 << (k - s - 1)]);
            let h = 1usize << s;
            let mut v = Vec::with_capacity(h);
            let mut cur = F::ONE;
            for _ in 0..h {
                v.push(cur);
                cur *= w;
            }
            v
        })
        .collect()
}

/// Decimation-in-frequency transform; leaves the output in bit-reversed order.
///
/// With `shift`, coefficient `i` is multiplied by `shift^i` while the first
/// pass loads it.
fn dif<F: PastaField, const PARALLEL: bool>(
    a: &mut [F],
    tw: &[Vec<F>],
    shift: Option<CosetShift<'_, F>>,
    cancellation: Option<&CancellationToken>,
) {
    let n = a.len();
    if n <= 1 {
        // A single coefficient is its own evaluation; shift^0 = 1.
        return;
    }
    dif_stages::<_, PARALLEL>(a, tw, shift, tw.len(), cancellation);
}

/// Finish a transform after any already-completed outer stages.
fn dif_stages<F: PastaField, const PARALLEL: bool>(
    a: &mut [F],
    tw: &[Vec<F>],
    shift: Option<CosetShift<'_, F>>,
    mut s: usize,
    cancellation: Option<&CancellationToken>,
) {
    let n = a.len();
    let mut first = true;
    while s >= 2 {
        if CancellationToken::checkpoint(cancellation).is_err() {
            return;
        }
        // Fused stages with half sizes 2m (outer) and m (inner).
        let m = 1usize << (s - 2);
        let outer = &tw[s - 1]; // w_{4m}^j, j < 2m
        let inner = &tw[s - 2]; // w_{2m}^j, j < m
        let pass_shift = if first { shift } else { None };
        dif_pass4::<_, PARALLEL>(a, m, outer, inner, pass_shift, cancellation);
        first = false;
        s -= 2;
    }
    if s == 1 {
        // Final radix-2 stage with half size 1: twiddle 1.
        if let (true, Some(shift)) = (first, shift) {
            // k == 1: apply the shift to coefficient 1 before the stage.
            a[1] *= match shift {
                CosetShift::Geometric(value) => value,
                CosetShift::Prepared(powers) => powers[1],
            };
        }
        let body = |chunk: &mut [F]| {
            if CancellationToken::checkpoint(cancellation).is_err() {
                return;
            }
            for pair in chunk.chunks_exact_mut(2) {
                let (x, y) = (pair[0], pair[1]);
                pair[0] = x + y;
                pair[1] = x - y;
            }
        };
        if PARALLEL && n >= PARALLEL_MIN {
            a.par_chunks_mut(PARALLEL_MIN).for_each(body);
        } else {
            body(a);
        }
    }
}

/// Shared two-stage butterfly; preserves the exact in-place operation order.
#[inline]
fn dif_butterfly4<F: PastaField>(
    [a0, a1, a2, a3]: [F; 4],
    m: usize,
    outer: &[F],
    inner: &[F],
    j: usize,
) -> [F; 4] {
    let y0 = a0 + a2;
    let y1 = a1 + a3;
    let (y2, y3) = if j == 0 {
        (a0 - a2, (a1 - a3) * outer[m])
    } else {
        ((a0 - a2) * outer[j], (a1 - a3) * outer[j + m])
    };
    let r0 = y0 + y1;
    let r2 = y2 + y3;
    let (r1, r3) = if j == 0 {
        (y0 - y1, y2 - y3)
    } else {
        let w = inner[j];
        ((y0 - y1) * w, (y2 - y3) * w)
    };
    [r0, r1, r2, r3]
}

/// Reads the first pass directly from immutable coefficients into its output.
fn dif_from<F: PastaField, const PARALLEL: bool>(
    coefficients: &[F],
    output: &mut [F],
    tw: &[Vec<F>],
    powers: &[F],
    cancellation: Option<&CancellationToken>,
) {
    if CancellationToken::checkpoint(cancellation).is_err() {
        return;
    }
    let n = output.len();
    if n == 1 {
        output[0] = coefficients[0];
        return;
    }
    if n == 2 {
        let x = coefficients[0];
        let y = coefficients[1] * powers[1];
        output[0] = x + y;
        output[1] = x - y;
        return;
    }
    let k = tw.len();
    let m = n / 4;
    let outer = &tw[k - 1];
    let inner = &tw[k - 2];
    let butterfly = |q0: &mut [F], q1: &mut [F], q2: &mut [F], q3: &mut [F], j0: usize| {
        for (off, (((x0, x1), x2), x3)) in q0
            .iter_mut()
            .zip(q1.iter_mut())
            .zip(q2.iter_mut())
            .zip(q3.iter_mut())
            .enumerate()
        {
            if off % 1024 == 0 && CancellationToken::checkpoint(cancellation).is_err() {
                return;
            }
            let j = j0 + off;
            let a = [
                coefficients[j] * powers[j],
                coefficients[j + m] * powers[j + m],
                coefficients[j + 2 * m] * powers[j + 2 * m],
                coefficients[j + 3 * m] * powers[j + 3 * m],
            ];
            let [r0, r1, r2, r3] = dif_butterfly4(a, m, outer, inner, j);
            *x0 = r0;
            *x1 = r1;
            *x2 = r2;
            *x3 = r3;
        }
    };
    let (q0, rest) = output.split_at_mut(m);
    let (q1, rest) = rest.split_at_mut(m);
    let (q2, q3) = rest.split_at_mut(m);
    if PARALLEL && n >= PARALLEL_MIN {
        // Same scheduling as the single large block of the in-place first pass.
        let chunk = (m / (rayon::current_num_threads() * 2))
            .max(256)
            .min(m)
            .max(1);
        q0.par_chunks_mut(chunk)
            .zip(q1.par_chunks_mut(chunk))
            .zip(q2.par_chunks_mut(chunk))
            .zip(q3.par_chunks_mut(chunk))
            .enumerate()
            .for_each(|(c, (((c0, c1), c2), c3))| butterfly(c0, c1, c2, c3, c * chunk));
    } else {
        butterfly(q0, q1, q2, q3, 0);
    }
    dif_stages::<_, PARALLEL>(output, tw, None, k - 2, cancellation);
}

/// One fused DIF pass over blocks of `4m`.
fn dif_pass4<F: PastaField, const PARALLEL: bool>(
    a: &mut [F],
    m: usize,
    outer: &[F],
    inner: &[F],
    shift: Option<CosetShift<'_, F>>,
    cancellation: Option<&CancellationToken>,
) {
    let n = a.len();
    let block = 4 * m;
    // The shift only occurs in the first pass, where the block is the whole
    // array, so element j + q*m sits at original index j + q*m.
    let quarter_shift = match shift {
        Some(CosetShift::Geometric(sh)) => {
            let sm = sh.pow_vartime([m as u64]);
            let s2m = sm.square();
            Some((sh, [F::ONE, sm, s2m, s2m * sm]))
        }
        _ => None,
    };
    let powers = match shift {
        Some(CosetShift::Prepared(powers)) => Some(powers),
        _ => None,
    };
    let butterfly = |q0: &mut [F], q1: &mut [F], q2: &mut [F], q3: &mut [F], j0: usize| {
        let mut sj = quarter_shift.map(|(sh, _)| sh.pow_vartime([j0 as u64]));
        for (off, (((x0, x1), x2), x3)) in q0
            .iter_mut()
            .zip(q1.iter_mut())
            .zip(q2.iter_mut())
            .zip(q3.iter_mut())
            .enumerate()
        {
            if off % 1024 == 0 && CancellationToken::checkpoint(cancellation).is_err() {
                return;
            }
            let j = j0 + off;
            let (mut a0, mut a1, mut a2, mut a3) = (*x0, *x1, *x2, *x3);
            if let (Some(s), Some((sh, c))) = (sj.as_mut(), quarter_shift.as_ref()) {
                a0 *= *s;
                a1 *= *s * c[1];
                a2 *= *s * c[2];
                a3 *= *s * c[3];
                *s *= sh;
            }
            if let Some(powers) = powers {
                a0 *= powers[j];
                a1 *= powers[j + m];
                a2 *= powers[j + 2 * m];
                a3 *= powers[j + 3 * m];
            }
            let [r0, r1, r2, r3] = dif_butterfly4([a0, a1, a2, a3], m, outer, inner, j);
            *x0 = r0;
            *x1 = r1;
            *x2 = r2;
            *x3 = r3;
        }
    };
    let blocks = n / block;
    if !PARALLEL || n < PARALLEL_MIN || blocks >= rayon::current_num_threads() * 4 {
        let run = |blk: &mut [F]| {
            let (q0, rest) = blk.split_at_mut(m);
            let (q1, rest) = rest.split_at_mut(m);
            let (q2, q3) = rest.split_at_mut(m);
            butterfly(q0, q1, q2, q3, 0);
        };
        if !PARALLEL || n < PARALLEL_MIN {
            a.chunks_exact_mut(block).for_each(run);
        } else {
            a.par_chunks_exact_mut(block).for_each(run);
        }
    } else {
        // Few large blocks: split each block's j range across the pool.
        let chunk = (m / (rayon::current_num_threads() * 2))
            .max(256)
            .min(m)
            .max(1);
        for blk in a.chunks_exact_mut(block) {
            let (q0, rest) = blk.split_at_mut(m);
            let (q1, rest) = rest.split_at_mut(m);
            let (q2, q3) = rest.split_at_mut(m);
            q0.par_chunks_mut(chunk)
                .zip(q1.par_chunks_mut(chunk))
                .zip(q2.par_chunks_mut(chunk))
                .zip(q3.par_chunks_mut(chunk))
                .enumerate()
                .for_each(|(c, (((c0, c1), c2), c3))| butterfly(c0, c1, c2, c3, c * chunk));
        }
    }
}

/// Bit-reverses the order of `a` (length `2^k`) and, with `scale = (c, s)`,
/// multiplies the element at natural index `i` by `c * s^i`.
fn bit_reverse_scale<F: PastaField, const PARALLEL: bool>(
    a: &mut [F],
    k: u32,
    scale: Option<(F, F)>,
    cancellation: Option<&CancellationToken>,
) {
    let n = a.len();
    if k > 0 {
        let shift = usize::BITS - k;
        for i in 0..n {
            if i % 4096 == 0 && CancellationToken::checkpoint(cancellation).is_err() {
                return;
            }
            let r = i.reverse_bits() >> shift;
            if i < r {
                a.swap(i, r);
            }
        }
    }
    if let Some((c, s)) = scale {
        let unit_shift = s == F::ONE;
        let body = |(ci, chunk): (usize, &mut [F])| {
            if CancellationToken::checkpoint(cancellation).is_err() {
                return;
            }
            if unit_shift {
                // Plain inverse transform: one multiplication per element.
                for x in chunk {
                    *x *= c;
                }
                return;
            }
            let start = ci * PARALLEL_MIN;
            let mut f = c * s.pow_vartime([start as u64]);
            for x in chunk {
                *x *= f;
                f *= s;
            }
        };
        if PARALLEL && n >= PARALLEL_MIN {
            a.par_chunks_mut(PARALLEL_MIN).enumerate().for_each(body);
        } else {
            a.chunks_mut(PARALLEL_MIN).enumerate().for_each(body);
        }
    }
}

/// Reference `O(n^2)` evaluation of `a` at `shift * omega^i` (tests and
/// differential checks only).
pub fn naive_coset_dft<F: PastaField>(a: &[F], omega: F, shift: F) -> Vec<F> {
    let n = a.len();
    let mut out = Vec::with_capacity(n);
    let mut x = shift;
    for _ in 0..n {
        // Horner evaluation at x.
        let v = a.iter().rev().fold(F::ZERO, |acc, c| acc * x + c);
        out.push(v);
        x *= omega;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::{Fp, Fq};
    use ff::Field;
    use rand_chacha::ChaCha20Rng;
    use rand_core_06::SeedableRng;

    fn random_vec<F: PastaField>(n: usize, seed: u64) -> Vec<F> {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        (0..n).map(|_| F::random(&mut rng)).collect()
    }

    #[test]
    fn small_sizes_match_naive() {
        for k in 0..=9u32 {
            let d = FftDomain::<Fp>::new(k).unwrap();
            let a = random_vec::<Fp>(1 << k, u64::from(k));
            let mut b = a.clone();
            d.fft(&mut b).unwrap();
            assert_eq!(b, naive_coset_dft(&a, d.omega(), Fp::ONE), "k = {k}");
            d.ifft(&mut b).unwrap();
            assert_eq!(b, a);
            let shift = <Fp as ff::WithSmallOrderMulGroup<3>>::ZETA;
            let mut c = a.clone();
            d.coset_fft(&mut c, shift).unwrap();
            assert_eq!(c, naive_coset_dft(&a, d.omega(), shift), "coset k = {k}");
            d.coset_ifft(&mut c, shift).unwrap();
            assert_eq!(c, a);
        }
    }

    #[test]
    fn batched_cosets_match_single_transforms_and_naive_dft() {
        fn check<F: PastaField>() {
            for workers in [1, 4] {
                let pool = rayon::ThreadPoolBuilder::new()
                    .num_threads(workers)
                    .build()
                    .unwrap();
                pool.install(|| {
                    for k in [0, 1, 2, 3, 4, 7, 12, 13] {
                        let domain = FftDomain::<F>::new(k).unwrap();
                        for count in [0u64, 1, 3, 17] {
                            let original: Vec<Vec<F>> = (0..count)
                                .map(|index| random_vec(domain.n(), index + 97))
                                .collect();
                            for shift in [F::ONE, F::from(7)] {
                                let mut batch = original.clone();
                                let addresses: Vec<_> = batch.iter().map(Vec::as_ptr).collect();
                                let mut columns: Vec<_> =
                                    batch.iter_mut().map(Vec::as_mut_slice).collect();
                                domain.coset_fft_many(&mut columns, shift).unwrap();
                                for (index, (values, source)) in
                                    batch.iter_mut().zip(&original).enumerate()
                                {
                                    let mut single = source.clone();
                                    domain.coset_fft(&mut single, shift).unwrap();
                                    assert_eq!(*values, single, "k={k} count={count}");
                                    assert_eq!(values.as_ptr(), addresses[index]);
                                    if k <= 4 {
                                        assert_eq!(
                                            *values,
                                            naive_coset_dft(source, domain.omega(), shift)
                                        );
                                    }
                                    domain.coset_ifft(values, shift).unwrap();
                                    assert_eq!(values, source);
                                }
                            }
                        }
                    }
                });
            }
        }
        check::<Fp>();
        check::<Fq>();
    }

    #[test]
    fn batched_coset_errors_leave_every_column_untouched() {
        fn check<F: PastaField>() {
            let domain = FftDomain::<F>::new(3).unwrap();
            let original = vec![random_vec::<F>(8, 1), random_vec(8, 2), random_vec(8, 3)];
            for bad_index in 0..original.len() {
                let mut batch = original.clone();
                batch[bad_index].pop();
                let before = batch.clone();
                let mut columns: Vec<_> = batch.iter_mut().map(Vec::as_mut_slice).collect();
                // Validate the entire batch before starting even the first transform.
                assert_eq!(
                    domain.coset_fft_many(&mut columns, F::ZERO),
                    Err(FftError::WrongLength {
                        expected: 8,
                        actual: 7
                    })
                );
                assert_eq!(batch, before);
            }
            let mut batch = original.clone();
            let mut columns: Vec<_> = batch.iter_mut().map(Vec::as_mut_slice).collect();
            assert_eq!(
                domain.coset_fft_many(&mut columns, F::ZERO),
                Err(FftError::ZeroShift)
            );
            assert_eq!(batch, original);
            assert_eq!(
                domain.coset_fft_many(&mut [], F::ZERO),
                Err(FftError::ZeroShift)
            );
            assert_eq!(domain.coset_fft_many(&mut [], F::ONE), Ok(()));
        }
        check::<Fp>();
        check::<Fq>();
    }

    #[test]
    fn domain_parameters() {
        let d = FftDomain::<Fq>::new(10).unwrap();
        assert_eq!(d.n(), 1024);
        assert_eq!(d.k(), 10);
        assert_eq!(d.omega().pow_vartime([1024u64]), Fq::ONE);
        assert_ne!(d.omega().pow_vartime([512u64]), Fq::ONE);
        assert_eq!(d.omega() * d.omega_inv(), Fq::ONE);
        assert_eq!(d.n_inv() * Fq::from(1024u64), Fq::ONE);
        assert!(d.twiddle_bytes() > 0);
        assert_eq!(
            FftDomain::<Fq>::new(33).unwrap_err(),
            FftError::UnsupportedSize { k: 33 }
        );
        let mut short = vec![Fq::ZERO; 3];
        assert_eq!(
            d.fft(&mut short),
            Err(FftError::WrongLength {
                expected: 1024,
                actual: 3
            })
        );
        assert_eq!(
            FftError::UnsupportedSize { k: 40 }.to_string(),
            "unsupported FFT size 2^40"
        );
    }

    #[test]
    fn zero_coset_shift_is_rejected_without_touching_the_input() {
        let d = FftDomain::<Fp>::new(3).unwrap();
        let a = random_vec::<Fp>(8, 21);
        let mut b = a.clone();
        assert_eq!(d.coset_ifft(&mut b, Fp::ZERO), Err(FftError::ZeroShift));
        assert_eq!(b, a);
        assert_eq!(d.coset_fft(&mut b, Fp::ZERO), Err(FftError::ZeroShift));
        assert_eq!(b, a);
        assert_eq!(FftError::ZeroShift.to_string(), "FFT coset shift is zero");
        assert_eq!(check_shift(&Fp::ONE), Ok(()));
        // Length errors take precedence, as before.
        assert!(matches!(
            d.coset_ifft(&mut b[..3], Fp::ZERO),
            Err(FftError::WrongLength { .. })
        ));
    }

    #[test]
    fn stage_twiddles_are_powers() {
        let w = FftDomain::<Fp>::new(4).unwrap().omega();
        let tw = stage_twiddles(w, 4);
        assert_eq!(tw.len(), 4);
        assert_eq!(tw[3][1], w);
        assert_eq!(tw[0], vec![Fp::ONE]);
    }

    #[test]
    fn bit_reverse_scale_permutes() {
        let mut a: Vec<Fp> = (0..8u64).map(Fp::from).collect();
        bit_reverse_scale::<_, true>(&mut a, 3, None, None);
        let expected: Vec<Fp> = [0u64, 4, 2, 6, 1, 5, 3, 7]
            .into_iter()
            .map(Fp::from)
            .collect();
        assert_eq!(a, expected);
        let mut b = vec![Fp::ONE; 4];
        bit_reverse_scale::<_, true>(&mut b, 2, Some((Fp::from(3u64), Fp::from(2u64))), None);
        assert_eq!(
            b,
            vec![
                Fp::from(3u64),
                Fp::from(6u64),
                Fp::from(12u64),
                Fp::from(24u64)
            ]
        );
    }

    #[test]
    fn dif_pass_and_naive_dft_agree_on_impulse() {
        let d = FftDomain::<Fp>::new(3).unwrap();
        let mut a = vec![Fp::ZERO; 8];
        a[1] = Fp::ONE;
        d.fft(&mut a).unwrap();
        let mut x = Fp::ONE;
        for v in a {
            assert_eq!(v, x);
            x *= d.omega();
        }
        let mut b = vec![Fp::ONE; 8];
        dif::<_, true>(&mut b, &stage_twiddles(d.omega(), 3), None, None);
        assert_eq!(b[0], Fp::from(8u64));
    }
}

#[cfg(test)]
#[path = "fft_plan_tests.rs"]
mod plan_tests;
