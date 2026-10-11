//! The proving key and the exact quotient cosets.
//!
//! # Exact cosets
//!
//! The quotient `h` has degree below `(d - 1) n`. Instead of an extended
//! domain of size `2^e >= (d - 1) n`, the prover evaluates on exactly `d - 1`
//! cosets of the size-`n` subgroup `H` ([`QuotientDomain`]):
//!
//! - coset `c` is `s_c H` with `s_c = ZETA * omega_e^c`, where `omega_e` is
//!   the `2^e`-th root of unity and `e = k + ceil(log2(d - 1))` (the vendored
//!   extended-domain cosets, of which only the first `d - 1` are used);
//! - on coset `c`, `X^n - 1` is the constant `lambda_c - 1` with
//!   `lambda_c = s_c^n`, so the vanishing division is one multiplication by
//!   [`QuotientDomain::vanishing_inverse`];
//! - [`QuotientDomain::recombine`] turns the `d - 1` coset evaluations back
//!   into the `(d - 1) n` coefficients of `h` with a small Vandermonde solve:
//!   the coset inverse transform of coset `c` yields
//!   `a_c[r] = sum_t h[t n + r] lambda_c^t`.
//!
//! The `lambda_c` are distinct (`omega_e^n` has order `2^(e-k) >= d - 1`) and
//! differ from 1 (`ZETA` has order 3), so both steps are well defined. `h` is
//! the same polynomial as with the vendored extended domain, so proof bytes
//! are unchanged.
//!
//! # The key
//!
//! [`ProvingKey`] owns the verifying key, the descriptor binding, the
//! selector-substituted constraint system and its selector plan
//! ([`KeyConstraintSystem`]; the selector columns live once, as the last
//! fixed columns), the fixed and permutation (`sigma`) columns
//! in evaluation and coefficient form, the masks `l_0`, `l_last` and
//! `l_active = 1 - l_last - l_blind`, the fixed-coset cache and optional
//! commitment-key tables, and the digest of the copy mapping it was built
//! from ([`ProvingKey::copy_digest`]), which is how a synthesized circuit is
//! checked against the key without recomputing `sigma`. The cache holds
//! every fixed and `sigma` polynomial evaluated on every quotient coset
//! ([`CosetCachePolicy::Eager`]), or nothing, in which case
//! [`ProvingKey::coset_values`] computes the same values on demand
//! ([`CosetCachePolicy::OnDemand`]).
//!
//! The masks are never cached: [`ProvingKey::coset_masks`] computes them on
//! a coset from their closed forms. With `x_i = s_c omega^i`,
//! `l_0(x_i) = (lambda_c - 1) / (n (x_i - 1))` (one batch inversion), and
//! `l_r(x_i) = l_0(x_{i - r})`, so `l_last` is a rotation of `l_0` and
//! `l_active = 1 - sum_{r = u}^{n - 1} l_r` a sliding sum of `b + 1` of its
//! rotations. The values equal the coset FFT of the mask polynomials.

use std::borrow::Cow;

pub mod artifact;

use ff::{BatchInvert, Field, WithSmallOrderMulGroup};
use iroha_pasta::{PastaCurve, PastaField, fft::FftDomain};

use super::{DescriptorBinding, KeyError, check_shape, vk::VerifyingKey};
use crate::{
    cs::{ConstraintSystem, FinalizedConstraintSystem, SelectorPlan},
    pcs::ipa::commit::CommitmentTables,
};

/// The exact quotient cosets of a circuit (see the module documentation).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuotientDomain<F: PastaField> {
    k: u32,
    n: usize,
    shifts: Vec<F>,
    lambdas: Vec<F>,
    vanishing_inverses: Vec<F>,
    /// `recombination[t][c]`: the coefficient of `Y^t` in the Lagrange basis
    /// polynomial of `lambda_c` (the inverse Vandermonde matrix).
    recombination: Vec<Vec<F>>,
}

/// `ceil(log2(value))` for `value >= 1`.
fn ceil_log2(value: usize) -> u32 {
    value.next_power_of_two().trailing_zeros()
}

impl<F: PastaField> QuotientDomain<F> {
    /// The `d - 1` cosets for degree `degree` at `k`.
    ///
    /// # Errors
    ///
    /// [`KeyError::UnsupportedDegree`] for `degree < 3` or when
    /// `k + ceil(log2(d - 1))` exceeds the field's 2-adicity.
    pub fn new(k: u32, degree: usize) -> Result<Self, KeyError> {
        let unsupported = || KeyError::UnsupportedDegree { degree };
        let pieces = degree
            .checked_sub(1)
            .filter(|pieces| *pieces >= 2)
            .ok_or_else(unsupported)?;
        let extended = k.checked_add(ceil_log2(pieces)).ok_or_else(unsupported)?;
        if extended > F::S || k >= usize::BITS {
            return Err(unsupported());
        }
        let n = 1_usize << k;
        let mut omega_e = F::ROOT_OF_UNITY;
        for _ in extended..F::S {
            omega_e = omega_e.square();
        }
        let n_u64 = u64::try_from(n).map_err(|_| unsupported())?;
        let mut shifts = Vec::with_capacity(pieces);
        let mut shift = <F as WithSmallOrderMulGroup<3>>::ZETA;
        for _ in 0..pieces {
            shifts.push(shift);
            shift *= omega_e;
        }
        let lambdas: Vec<F> = shifts.iter().map(|s| s.pow_vartime([n_u64])).collect();
        let mut vanishing_inverses = Vec::with_capacity(pieces);
        for lambda in &lambdas {
            vanishing_inverses
                .push(Option::<F>::from((*lambda - F::ONE).invert()).ok_or_else(unsupported)?);
        }
        // Lagrange basis polynomials over the nodes lambda_c, in coefficient
        // form: recombination[t][c] = [Y^t] L_c(Y).
        let mut recombination = vec![vec![F::ZERO; pieces]; pieces];
        for (c, lambda_c) in lambdas.iter().enumerate() {
            let mut basis = vec![F::ONE];
            let mut denominator = F::ONE;
            for (m, lambda_m) in lambdas.iter().enumerate() {
                if m == c {
                    continue;
                }
                // basis *= (Y - lambda_m)
                let mut next = vec![F::ZERO; basis.len() + 1];
                for (i, coeff) in basis.iter().enumerate() {
                    next[i + 1] += coeff;
                    next[i] -= *coeff * lambda_m;
                }
                basis = next;
                denominator *= *lambda_c - lambda_m;
            }
            let inverse = Option::<F>::from(denominator.invert()).ok_or_else(unsupported)?;
            for (t, coeff) in basis.iter().enumerate() {
                recombination[t][c] = *coeff * inverse;
            }
        }
        Ok(Self {
            k,
            n,
            shifts,
            lambdas,
            vanishing_inverses,
            recombination,
        })
    }

    /// `log2(n)`.
    #[must_use]
    pub fn k(&self) -> u32 {
        self.k
    }

    /// The number of cosets, `d - 1`.
    #[must_use]
    pub fn pieces(&self) -> usize {
        self.shifts.len()
    }

    /// The shift `s_c` of coset `c`.
    #[must_use]
    pub fn shift(&self, coset: usize) -> Option<F> {
        self.shifts.get(coset).copied()
    }

    /// `(s_c^n - 1)^-1`, the inverse of `X^n - 1` on coset `c`.
    #[must_use]
    pub fn vanishing_inverse(&self, coset: usize) -> Option<F> {
        self.vanishing_inverses.get(coset).copied()
    }

    /// Evaluates the polynomial with `n` coefficients `coeffs` on coset `c`.
    ///
    /// # Errors
    ///
    /// [`KeyError::CosetIndex`] for a missing coset; [`KeyError::Fft`] for a
    /// wrong length.
    pub fn evaluate(
        &self,
        domain: &FftDomain<F>,
        coeffs: &[F],
        coset: usize,
    ) -> Result<Vec<F>, KeyError> {
        self.evaluate_cancellable(domain, coeffs, coset, None)
    }
    /// Evaluate a coset with an explicit operation signal.
    /// # Errors
    /// As [`Self::evaluate`], or cooperative cancellation.
    pub fn evaluate_cancellable(
        &self,
        domain: &FftDomain<F>,
        coeffs: &[F],
        coset: usize,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<Vec<F>, KeyError> {
        iroha_pasta::CancellationToken::checkpoint(cancellation)?;
        let shift = self.shift(coset).ok_or(KeyError::CosetIndex)?;
        let mut values = coeffs.to_vec();
        domain.coset_fft_cancellable(&mut values, shift, cancellation)?;
        Ok(values)
    }

    /// Recovers the `(d - 1) n` coefficients of a polynomial of degree below
    /// `(d - 1) n` from its evaluations on the `d - 1` cosets.
    ///
    /// # Errors
    ///
    /// [`KeyError::Shape`] unless there are `d - 1` vectors of `n` values;
    /// [`KeyError::Fft`] on transform failure.
    pub fn recombine(
        &self,
        domain: &FftDomain<F>,
        coset_values: Vec<Vec<F>>,
    ) -> Result<Vec<F>, KeyError> {
        self.recombine_cancellable(domain, coset_values, None)
    }

    /// Recombines quotient cosets with an explicit operation signal.
    ///
    /// # Errors
    /// As [`Self::recombine`], or [`KeyError::Cancelled`].
    pub fn recombine_cancellable(
        &self,
        domain: &FftDomain<F>,
        coset_values: Vec<Vec<F>>,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<Vec<F>, KeyError> {
        let mut residues = crate::secret::SecretColumns::new(coset_values);
        iroha_pasta::CancellationToken::checkpoint(cancellation)?;
        check_shape("coset evaluations", self.pieces(), residues.len())?;
        for (values, shift) in residues.iter_mut().zip(&self.shifts) {
            check_shape("coset values", self.n, values.len())?;
            domain.coset_ifft_cancellable(values, *shift, cancellation)?;
        }
        let pieces = self.pieces();
        let mut coeffs = crate::secret::SecretPolynomial::new(vec![F::ZERO; pieces * self.n]);
        for (t, row) in self.recombination.iter().enumerate() {
            let out = &mut coeffs[t * self.n..(t + 1) * self.n];
            for (weight, residue) in row.iter().zip(residues.iter()) {
                for (target, value) in out.iter_mut().zip(residue) {
                    *target += *weight * value;
                }
            }
        }
        iroha_pasta::CancellationToken::checkpoint(cancellation)?;
        Ok(coeffs.into_vec())
    }

    /// `lambda_c = s_c^n`.
    #[must_use]
    pub fn lambda(&self, coset: usize) -> Option<F> {
        self.lambdas.get(coset).copied()
    }
}

/// Whether the proving key evaluates its fixed polynomials on the quotient
/// cosets ahead of time.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum CosetCachePolicy {
    /// Evaluate every fixed and `sigma` polynomial on every coset at key
    /// generation. The masks are never cached: [`ProvingKey::coset_masks`]
    /// computes them per coset from their closed forms.
    #[default]
    Eager,
    /// Keep no cache; [`ProvingKey::coset_values`] evaluates on demand.
    OnDemand,
}

/// A polynomial of the proving key evaluated on the quotient cosets
/// ([`ProvingKey::coset_values`]): a fixed or `sigma` polynomial (cached
/// under [`CosetCachePolicy::Eager`]) or a mask (never cached; computed per
/// coset by [`ProvingKey::coset_masks`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CosetPolynomial {
    /// Fixed column `i` (selector columns included).
    Fixed(usize),
    /// Permutation polynomial `sigma_j`.
    Permutation(usize),
    /// `l_0`.
    L0,
    /// `l_last`.
    LLast,
    /// `l_active = 1 - l_last - l_blind`.
    LActive,
}

/// `(l_0, l_last, l_active)` borrowed from a proving key.
pub type MaskSlices<'a, F> = (&'a [F], &'a [F], &'a [F]);

/// The masks on one quotient coset ([`ProvingKey::coset_masks`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CosetMasks<F> {
    /// `l_0`.
    pub l0: Vec<F>,
    /// `l_last`.
    pub l_last: Vec<F>,
    /// `l_active = 1 - l_last - l_blind`.
    pub l_active: Vec<F>,
}

/// The constraint system a proving key keeps: the selector-substituted
/// system and its selector plan. The selector columns themselves are not
/// kept twice: they are the key's last fixed columns
/// ([`ProvingKey::selector_values`]), so no accessor here can return them
/// empty.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyConstraintSystem<F> {
    cs: ConstraintSystem<F>,
    plan: SelectorPlan,
}

impl<F> KeyConstraintSystem<F> {
    /// Splits a finalized system into the kept system and its selector
    /// columns.
    pub(crate) fn split(finalized: FinalizedConstraintSystem<F>) -> (Self, Vec<Vec<F>>) {
        let (cs, columns, plan) = finalized.into_parts();
        (Self { cs, plan }, columns)
    }

    /// The constraint system after substitution (no selector nodes remain).
    #[must_use]
    pub const fn constraint_system(&self) -> &ConstraintSystem<F> {
        &self.cs
    }

    /// The selector plan.
    #[must_use]
    pub const fn selector_plan(&self) -> &SelectorPlan {
        &self.plan
    }
}

/// The masks in evaluation and coefficient form.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Masks<F> {
    l0: Vec<F>,
    l_last: Vec<F>,
    l_active: Vec<F>,
}

/// A proving key (see the module documentation).
#[derive(Clone, Debug)]
pub struct ProvingKey<C: PastaCurve> {
    vk: VerifyingKey<C>,
    binding: DescriptorBinding,
    constraint_system: KeyConstraintSystem<C::ScalarExt>,
    domain: FftDomain<C::ScalarExt>,
    quotient: QuotientDomain<C::ScalarExt>,
    fixed_values: Vec<Vec<C::ScalarExt>>,
    fixed_polys: Vec<Vec<C::ScalarExt>>,
    permutation_values: Vec<Vec<C::ScalarExt>>,
    permutation_polys: Vec<Vec<C::ScalarExt>>,
    mask_values: Masks<C::ScalarExt>,
    mask_polys: Masks<C::ScalarExt>,
    /// `cache[poly][coset]` in [`ProvingKey::cache_order`] order.
    cache: Option<Vec<Vec<Vec<C::ScalarExt>>>>,
    tables: CommitmentTables<C>,
    /// [`PermutationAssembly::mapping_digest`](crate::cs::PermutationAssembly::mapping_digest)
    /// of the copies the key was generated from.
    copy_digest: [u8; 32],
}

/// Interpolates evaluation-form columns.
fn interpolate_all<F: PastaField>(
    domain: &FftDomain<F>,
    columns: &[Vec<F>],
    cancellation: Option<&iroha_pasta::CancellationToken>,
) -> Result<Vec<Vec<F>>, KeyError> {
    columns
        .iter()
        .map(|column| {
            let mut coeffs = column.clone();
            domain.ifft_cancellable(&mut coeffs, cancellation)?;
            Ok(coeffs)
        })
        .collect()
}

impl<C: PastaCurve> ProvingKey<C> {
    /// Assembles a proving key.
    ///
    /// # Errors
    ///
    /// [`KeyError::Shape`] when the columns do not match the descriptor;
    /// [`KeyError::UnsupportedDegree`] or [`KeyError::Fft`] from the domains,
    /// or [`KeyError::Cancelled`] after all arithmetic tasks join.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_cancellable(
        vk: VerifyingKey<C>,
        binding: DescriptorBinding,
        constraint_system: KeyConstraintSystem<C::ScalarExt>,
        fixed_values: Vec<Vec<C::ScalarExt>>,
        permutation_values: Vec<Vec<C::ScalarExt>>,
        copy_digest: [u8; 32],
        policy: CosetCachePolicy,
        tables: CommitmentTables<C>,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<Self, KeyError> {
        iroha_pasta::CancellationToken::checkpoint(cancellation)?;
        let descriptor = binding.descriptor();
        let k = u32::from(descriptor.k);
        let n = binding.n();
        check_shape(
            "fixed columns",
            descriptor.num_fixed_columns as usize,
            fixed_values.len(),
        )?;
        check_shape(
            "permutation columns",
            descriptor.permutation.len(),
            permutation_values.len(),
        )?;
        for column in fixed_values.iter().chain(&permutation_values) {
            check_shape("column rows", n, column.len())?;
        }
        let domain = FftDomain::new(k)?;
        let quotient = QuotientDomain::new(k, usize::from(descriptor.degree))?;
        let fixed_polys = interpolate_all(&domain, &fixed_values, cancellation)?;
        let permutation_polys = interpolate_all(&domain, &permutation_values, cancellation)?;

        let blinding_rows = usize::from(descriptor.blinding_factors);
        let last = n - blinding_rows - 1;
        let mut l0 = vec![C::ScalarExt::ZERO; n];
        l0[0] = C::ScalarExt::ONE;
        let mut l_last = vec![C::ScalarExt::ZERO; n];
        l_last[last] = C::ScalarExt::ONE;
        let l_active: Vec<C::ScalarExt> = (0..n)
            .map(|row| {
                if row < last {
                    C::ScalarExt::ONE
                } else {
                    C::ScalarExt::ZERO
                }
            })
            .collect();
        let mask_values = Masks {
            l0,
            l_last,
            l_active,
        };
        let polys = interpolate_all(
            &domain,
            &[
                mask_values.l0.clone(),
                mask_values.l_last.clone(),
                mask_values.l_active.clone(),
            ],
            cancellation,
        )?;
        let [l0, l_last, l_active]: [Vec<C::ScalarExt>; 3] =
            polys.try_into().map_err(|_| KeyError::CosetIndex)?;
        let mask_polys = Masks {
            l0,
            l_last,
            l_active,
        };

        let mut key = Self {
            vk,
            binding,
            constraint_system,
            domain,
            quotient,
            fixed_values,
            fixed_polys,
            permutation_values,
            permutation_polys,
            mask_values,
            mask_polys,
            cache: None,
            tables,
            copy_digest,
        };
        if policy == CosetCachePolicy::Eager {
            let mut cache = Vec::new();
            for poly in key.cache_order() {
                let coeffs = key.coefficients(poly)?;
                let cosets = (0..key.quotient.pieces())
                    .map(|coset| {
                        key.quotient
                            .evaluate_cancellable(&key.domain, coeffs, coset, cancellation)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                cache.push(cosets);
            }
            key.cache = Some(cache);
        }
        iroha_pasta::CancellationToken::checkpoint(cancellation)?;
        Ok(key)
    }

    /// Every cached polynomial, in cache order (the masks are computed per
    /// coset, see [`Self::coset_masks`]).
    fn cache_order(&self) -> Vec<CosetPolynomial> {
        (0..self.fixed_polys.len())
            .map(CosetPolynomial::Fixed)
            .chain((0..self.permutation_polys.len()).map(CosetPolynomial::Permutation))
            .collect()
    }

    /// The position of `poly` in the cache order (`None` for the masks).
    fn cache_index(&self, poly: CosetPolynomial) -> Option<usize> {
        let fixed = self.fixed_polys.len();
        let permutation = self.permutation_polys.len();
        match poly {
            CosetPolynomial::Fixed(i) => (i < fixed).then_some(i),
            CosetPolynomial::Permutation(j) => (j < permutation).then_some(fixed + j),
            CosetPolynomial::L0 | CosetPolynomial::LLast | CosetPolynomial::LActive => None,
        }
    }

    /// `(l_0, l_last, l_active)` on quotient coset `coset`, from their
    /// closed forms (see the module documentation): one batch inversion and
    /// a sliding sum, equal to the coset FFT of the mask polynomials.
    ///
    /// # Errors
    ///
    /// [`KeyError::CosetIndex`] for a missing coset, and
    /// [`KeyError::Shape`] when the blinding rows do not fit the domain.
    pub fn coset_masks(&self, coset: usize) -> Result<CosetMasks<C::ScalarExt>, KeyError> {
        let shift = self.quotient.shift(coset).ok_or(KeyError::CosetIndex)?;
        let lambda = self.quotient.lambda(coset).ok_or(KeyError::CosetIndex)?;
        let n = self.domain.n();
        let blinding = usize::from(self.binding.descriptor().blinding_factors);
        let last = n
            .checked_sub(blinding)
            .and_then(|rows| rows.checked_sub(1))
            .ok_or(KeyError::Shape {
                what: "blinding rows",
                expected: n,
                actual: blinding,
            })?;
        let n_field = C::ScalarExt::from(u64::try_from(n).map_err(|_| KeyError::CosetIndex)?);
        let n_inv = Option::<C::ScalarExt>::from(n_field.invert()).ok_or(KeyError::CosetIndex)?;
        let factor = (lambda - C::ScalarExt::ONE) * n_inv;
        // l_0(x_i) = (lambda - 1) / (n (x_i - 1)); x_i != 1 since x_i^n =
        // lambda != 1.
        let omega = self.domain.omega();
        let mut l0 = Vec::with_capacity(n);
        let mut point = shift;
        for _ in 0..n {
            l0.push(point - C::ScalarExt::ONE);
            point *= omega;
        }
        l0.iter_mut().batch_invert();
        for value in &mut l0 {
            *value *= factor;
        }
        // l_r(x_i) = l_0(x_{i - r}).
        let rotated = |row: usize, rotation: usize| l0[(row + n - rotation) % n];
        let l_last: Vec<C::ScalarExt> = (0..n).map(|row| rotated(row, last)).collect();
        // sum_{r = last}^{n - 1} l_r(x_i) = sum_{t = 0}^{b} l_0(x_{i - last - t}),
        // slid one row at a time.
        let mut window: C::ScalarExt = (0..=blinding).map(|t| rotated(0, last + t)).sum();
        let mut l_active = Vec::with_capacity(n);
        for row in 0..n {
            l_active.push(C::ScalarExt::ONE - window);
            window += rotated(row + 1, last);
            window -= rotated(row + 1, last + blinding + 1);
        }
        Ok(CosetMasks {
            l0,
            l_last,
            l_active,
        })
    }

    /// The coefficients of a cached polynomial.
    fn coefficients(&self, poly: CosetPolynomial) -> Result<&[C::ScalarExt], KeyError> {
        let column = match poly {
            CosetPolynomial::Fixed(i) => self.fixed_polys.get(i),
            CosetPolynomial::Permutation(j) => self.permutation_polys.get(j),
            CosetPolynomial::L0 => Some(&self.mask_polys.l0),
            CosetPolynomial::LLast => Some(&self.mask_polys.l_last),
            CosetPolynomial::LActive => Some(&self.mask_polys.l_active),
        };
        column.map(Vec::as_slice).ok_or(KeyError::CosetIndex)
    }

    /// The evaluations of `poly` on quotient coset `coset`: borrowed from the
    /// cache, or computed (identically) when the key has none.
    ///
    /// # Errors
    ///
    /// [`KeyError::CosetIndex`] for a missing polynomial or coset.
    pub fn coset_values(
        &self,
        poly: CosetPolynomial,
        coset: usize,
    ) -> Result<Cow<'_, [C::ScalarExt]>, KeyError> {
        if coset >= self.quotient.pieces() {
            return Err(KeyError::CosetIndex);
        }
        if matches!(
            poly,
            CosetPolynomial::L0 | CosetPolynomial::LLast | CosetPolynomial::LActive
        ) {
            let masks = self.coset_masks(coset)?;
            return Ok(Cow::Owned(match poly {
                CosetPolynomial::L0 => masks.l0,
                CosetPolynomial::LLast => masks.l_last,
                _ => masks.l_active,
            }));
        }
        self.cache.as_ref().map_or_else(
            || {
                let coeffs = self.coefficients(poly)?;
                Ok(Cow::Owned(self.quotient.evaluate(
                    &self.domain,
                    coeffs,
                    coset,
                )?))
            },
            |cache| {
                let index = self.cache_index(poly).ok_or(KeyError::CosetIndex)?;
                Ok(Cow::Borrowed(cache[index][coset].as_slice()))
            },
        )
    }

    /// Whether the coset cache is populated.
    #[must_use]
    pub fn has_coset_cache(&self) -> bool {
        self.cache.is_some()
    }

    /// Bytes held by the coset cache.
    #[must_use]
    pub fn coset_cache_bytes(&self) -> usize {
        self.cache.as_ref().map_or(0, |cache| {
            cache
                .iter()
                .flatten()
                .map(Vec::len)
                .sum::<usize>()
                .saturating_mul(core::mem::size_of::<C::ScalarExt>())
        })
    }

    /// The verifying key.
    #[must_use]
    pub fn vk(&self) -> &VerifyingKey<C> {
        &self.vk
    }

    /// The descriptor binding.
    #[must_use]
    pub fn binding(&self) -> &DescriptorBinding {
        &self.binding
    }

    /// The selector-substituted constraint system and its selector plan.
    /// The selector column values are [`Self::selector_values`].
    #[must_use]
    pub fn constraint_system(&self) -> &KeyConstraintSystem<C::ScalarExt> {
        &self.constraint_system
    }

    /// The selector columns in evaluation form: the fixed columns from the
    /// descriptor's selector `first_column` on (empty when the descriptor's
    /// `first_column` is out of range, which a validated key never has).
    #[must_use]
    pub fn selector_values(&self) -> &[Vec<C::ScalarExt>] {
        usize::try_from(self.binding.descriptor().selectors.first_column)
            .ok()
            .and_then(|first| self.fixed_values.get(first..))
            .unwrap_or(&[])
    }

    /// The size-`n` FFT domain.
    #[must_use]
    pub fn domain(&self) -> &FftDomain<C::ScalarExt> {
        &self.domain
    }

    /// The exact quotient cosets.
    #[must_use]
    pub fn quotient_domain(&self) -> &QuotientDomain<C::ScalarExt> {
        &self.quotient
    }

    /// Fixed columns in evaluation form (selector columns included).
    #[must_use]
    pub fn fixed_values(&self) -> &[Vec<C::ScalarExt>] {
        &self.fixed_values
    }

    /// Fixed columns in coefficient form.
    #[must_use]
    pub fn fixed_polys(&self) -> &[Vec<C::ScalarExt>] {
        &self.fixed_polys
    }

    /// `sigma_j` in evaluation form.
    #[must_use]
    pub fn permutation_values(&self) -> &[Vec<C::ScalarExt>] {
        &self.permutation_values
    }

    /// The digest of the copy mapping the key was generated from
    /// ([`PermutationAssembly::mapping_digest`](crate::cs::PermutationAssembly::mapping_digest)).
    #[must_use]
    pub fn copy_digest(&self) -> &[u8; 32] {
        &self.copy_digest
    }

    /// `sigma_j` in coefficient form.
    #[must_use]
    pub fn permutation_polys(&self) -> &[Vec<C::ScalarExt>] {
        &self.permutation_polys
    }

    /// `(l_0, l_last, l_active)` in evaluation form.
    #[must_use]
    pub fn mask_values(&self) -> MaskSlices<'_, C::ScalarExt> {
        (
            &self.mask_values.l0,
            &self.mask_values.l_last,
            &self.mask_values.l_active,
        )
    }

    /// `(l_0, l_last, l_active)` in coefficient form.
    #[must_use]
    pub fn mask_polys(&self) -> MaskSlices<'_, C::ScalarExt> {
        (
            &self.mask_polys.l0,
            &self.mask_polys.l_last,
            &self.mask_polys.l_active,
        )
    }

    /// The commitment-key tables (possibly empty).
    #[must_use]
    pub fn commitment_tables(&self) -> &CommitmentTables<C> {
        &self.tables
    }

    /// The canonical encoding of `transcript_repr`.
    #[must_use]
    pub fn transcript_repr_bytes(&self) -> [u8; 32] {
        self.vk.transcript_repr().to_repr()
    }
}

#[cfg(test)]
mod tests {
    use iroha_pasta::{Fp, Fq};
    use rand_chacha::ChaCha20Rng;
    use rand_core_06::SeedableRng;

    use super::*;
    use crate::pcs::ipa::evaluate_polynomial;

    fn check_domain<F: PastaField>(k: u32, degree: usize) {
        let quotient = QuotientDomain::<F>::new(k, degree).expect("domain");
        let domain = FftDomain::<F>::new(k).expect("fft");
        let n = 1_usize << k;
        assert_eq!(quotient.pieces(), degree - 1);
        assert_eq!(quotient.k(), k);
        let mut rng = ChaCha20Rng::seed_from_u64(u64::from(k) * 31 + degree as u64);
        let coeffs: Vec<F> = (0..(degree - 1) * n).map(|_| F::random(&mut rng)).collect();
        let mut evaluations = Vec::new();
        for coset in 0..quotient.pieces() {
            let shift = quotient.shift(coset).expect("coset");
            let lambda = quotient.lambda(coset).expect("coset");
            assert_eq!(lambda, shift.pow_vartime([n as u64]));
            assert_eq!(
                quotient.vanishing_inverse(coset).expect("coset") * (lambda - F::ONE),
                F::ONE
            );
            // Direct evaluation of the long polynomial on the coset.
            let values: Vec<F> = (0..n)
                .map(|i| {
                    let point = shift * domain.omega().pow_vartime([i as u64]);
                    evaluate_polynomial(&coeffs, point)
                })
                .collect();
            evaluations.push(values);
        }
        assert_eq!(
            quotient
                .recombine(&domain, evaluations.clone())
                .expect("recombine"),
            coeffs
        );
        let cancelled = iroha_pasta::CancellationToken::new();
        cancelled.cancel();
        assert_eq!(
            quotient.recombine_cancellable(&domain, evaluations.clone(), Some(&cancelled)),
            Err(KeyError::Cancelled)
        );
        let fresh = iroha_pasta::CancellationToken::new();
        assert_eq!(
            quotient.recombine_cancellable(&domain, evaluations, Some(&fresh)),
            Ok(coeffs.clone())
        );
        // Evaluating an n-coefficient polynomial matches direct evaluation.
        let short: Vec<F> = coeffs[..n].to_vec();
        let on_coset = quotient.evaluate(&domain, &short, 1).expect("evaluate");
        let shift = quotient.shift(1).expect("coset");
        assert_eq!(
            on_coset[3],
            evaluate_polynomial(&short, shift * domain.omega().pow_vartime([3]))
        );
        assert_eq!(quotient.shift(degree), None);
        assert_eq!(
            quotient.evaluate(&domain, &short, degree).err(),
            Some(KeyError::CosetIndex)
        );
    }

    #[test]
    fn exact_cosets_recombine_the_quotient() {
        for degree in [3, 4, 5, 9] {
            check_domain::<Fp>(3, degree);
            check_domain::<Fq>(4, degree);
        }
        assert_eq!(
            QuotientDomain::<Fp>::new(4, 2).err(),
            Some(KeyError::UnsupportedDegree { degree: 2 })
        );
        assert_eq!(
            QuotientDomain::<Fp>::new(31, 9).err(),
            Some(KeyError::UnsupportedDegree { degree: 9 })
        );
    }

    #[test]
    fn exact_cosets_are_the_vendored_extended_cosets() {
        // s_c = ZETA * omega_e^c with omega_e the 2^(k+2)-th root for d = 5.
        let quotient = QuotientDomain::<Fp>::new(4, 5).expect("domain");
        let omega_e = FftDomain::<Fp>::new(6).expect("fft").omega();
        for coset in 0..4 {
            assert_eq!(
                quotient.shift(coset),
                Some(<Fp as WithSmallOrderMulGroup<3>>::ZETA * omega_e.pow_vartime([coset as u64]))
            );
        }
    }
}
