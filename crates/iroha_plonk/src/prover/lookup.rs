//! The halo2 permuted lookup (spec section 2 "Lookup", section 7 rows 2 and
//! 4, `BlindingScheduleV1` items 2 and 4).
//!
//! For each lookup the prover compresses the input and table expressions
//! with `theta` (`A = fold(acc * theta + a_i)`, likewise `S`), permutes the
//! usable rows into `(A', S')` exactly as the vendored prover does, pads
//! rows `u..n` of `A'` and then of `S'` with random values, draws the `A'`
//! and `S'` blinds and writes both commitments. After `beta` and `gamma` it
//! builds the grand product
//!
//! ```text
//! z(omega^0) = 1,
//! z(omega^(i+1)) = z(omega^i) (A_i + beta)(S_i + gamma) / ((A'_i + beta)(S'_i + gamma))
//! ```
//!
//! for `i < u`, fills rows `n-b..n` with random values, draws its blind and
//! writes its commitment.
//!
//! # The permutation
//!
//! The usable input rows are grouped by value in ascending canonical-integer
//! order. Group `g` (value `v`, count `c`) emits `(v, v)` and then `c - 1`
//! pairs `(v, t)` with `t` taken in order from the slice
//! `[start_g - g, end_g - g - 1)` of the leftover table values: the sorted
//! usable table values that repeat their predecessor or do not occur in the
//! input. An input value missing from the table is a prover error. The
//! permutation runs in time that depends on the (secret) values, like the
//! vendored one.

use crate::secret::SecretPolynomial;
use ff::Field;
use iroha_pasta::CancellationToken;
use iroha_pasta::{PastaCurve, PastaField, msm::MemoryBudget};
use rand_core_06::RngCore;

use super::{
    ProverError, batch::invert_column_cancellable, quotient::CompiledExpressions, random_values,
    write_point,
};
use crate::{
    keys::ProvingKey,
    pcs::ipa::{PinnedParams, commit::Secrecy},
    protocol::Shape,
    transcript::TranscriptWrite,
};

/// A lookup after its permuted columns are committed.
pub(super) struct Permuted<F: iroha_pasta::PastaField> {
    compressed_input: Vec<F>,
    compressed_table: Vec<F>,
    input_values: Vec<F>,
    table_values: Vec<F>,
    input_blind: F,
    table_blind: F,
}
impl<F: iroha_pasta::PastaField> Drop for Permuted<F> {
    fn drop(&mut self) {
        self.compressed_input
            .iter_mut()
            .for_each(crate::secret::wipe_one);
        self.compressed_table
            .iter_mut()
            .for_each(crate::secret::wipe_one);
        self.input_values
            .iter_mut()
            .for_each(crate::secret::wipe_one);
        self.table_values
            .iter_mut()
            .for_each(crate::secret::wipe_one);
        self.input_blind.zeroize();
        self.table_blind.zeroize();
    }
}

/// A lookup after its product is committed.
pub(super) struct Committed<F: iroha_pasta::PastaField> {
    /// `A'` in coefficient form.
    pub(super) input_poly: Vec<F>,
    /// The blind of `A'`.
    pub(super) input_blind: F,
    /// `S'` in coefficient form.
    pub(super) table_poly: Vec<F>,
    /// The blind of `S'`.
    pub(super) table_blind: F,
    /// `z` in coefficient form.
    pub(super) product_poly: Vec<F>,
    /// The blind of `z`.
    pub(super) product_blind: F,
}
impl<F: iroha_pasta::PastaField> Drop for Committed<F> {
    fn drop(&mut self) {
        self.input_poly.iter_mut().for_each(crate::secret::wipe_one);
        self.table_poly.iter_mut().for_each(crate::secret::wipe_one);
        self.product_poly
            .iter_mut()
            .for_each(crate::secret::wipe_one);
        self.input_blind.zeroize();
        self.table_blind.zeroize();
        self.product_blind.zeroize();
    }
}

/// How the prover permutes one lookup's usable rows into `(A', S')`, padded
/// to `n` rows (`A'` padding first, then `S'` padding).
///
/// Production proofs always use [`VendoredPermutation`]. The trait exists so
/// that the malicious-prover tests can substitute a forged permutation and
/// drive a lookup violation through the verifier while every other prover
/// step stays the real one.
pub(super) trait LookupPermutation<F> {
    /// Only the production membership-checking permutation opts into public
    /// fixed-table bounds. Malicious-prover strategies keep the original
    /// full-width commitment route so verifier-negative tests still form proofs.
    const PUBLIC_TABLE_BOUND: bool = false;

    /// The permuted input and table columns of lookup `lookup`.
    ///
    /// # Errors
    ///
    /// [`ProverError::LookupInputMissing`] when no permutation exists.
    fn permute<R: RngCore>(
        &mut self,
        input: &[F],
        table: &[F],
        usable_rows: usize,
        n: usize,
        lookup: usize,
        rng: &mut R,
    ) -> Result<(Vec<F>, Vec<F>), ProverError>;
}

/// The vendored permutation ([`permute`]), the only production strategy.
#[derive(Clone, Copy, Debug)]
pub(super) struct VendoredPermutation;

impl<F: PastaField> LookupPermutation<F> for VendoredPermutation {
    const PUBLIC_TABLE_BOUND: bool = true;

    fn permute<R: RngCore>(
        &mut self,
        input: &[F],
        table: &[F],
        usable_rows: usize,
        n: usize,
        lookup: usize,
        rng: &mut R,
    ) -> Result<(Vec<F>, Vec<F>), ProverError> {
        permute(input, table, usable_rows, n, lookup, rng)
    }
}

/// The vendored permutation of the usable rows of `input` and `table`
/// (see the module documentation), padded to `n` rows: `A'` padding first,
/// then `S'` padding.
///
/// # Errors
///
/// [`ProverError::LookupInputMissing`] when an input value is not in the
/// table.
pub(super) fn permute<F: PastaField, R: RngCore>(
    input: &[F],
    table: &[F],
    usable_rows: usize,
    n: usize,
    lookup: usize,
    rng: &mut R,
) -> Result<(Vec<F>, Vec<F>), ProverError> {
    let missing = || ProverError::LookupInputMissing { lookup };
    let input = input.get(..usable_rows).ok_or_else(missing)?;
    let table = table.get(..usable_rows).ok_or_else(missing)?;
    let pad = n.checked_sub(usable_rows).ok_or_else(missing)?;
    // Field ordering converts both operands out of Montgomery form on each
    // comparison. Convert once, then sort compact integer keys in precisely
    // the same canonical order, without a tree allocation for every group.
    let mut sorted_input =
        zeroize::Zeroizing::new(input.iter().map(canonical_key).collect::<Vec<_>>());
    sorted_input.sort_unstable();
    let mut sorted_table =
        zeroize::Zeroizing::new(table.iter().map(canonical_key).collect::<Vec<_>>());
    sorted_table.sort_unstable();
    let mut groups = sorted_input
        .chunk_by(|left, right| left == right)
        .peekable();
    let mut leftover = zeroize::Zeroizing::new(Vec::with_capacity(usable_rows));
    for value in sorted_table.iter().copied() {
        if let Some(group) = groups.peek() {
            if group[0] < value {
                return Err(missing());
            }
            if group[0] == value {
                // Consume exactly one table entry per input group. Later
                // duplicates and values absent from the input stay ordered.
                groups.next();
                continue;
            }
        }
        leftover.push(value);
    }
    if groups.next().is_some() {
        return Err(missing());
    }
    let mut permuted_input = SecretPolynomial::new(Vec::with_capacity(n));
    let mut permuted_table = SecretPolynomial::new(Vec::with_capacity(n));
    let mut leftover = leftover.iter().copied();
    for group in sorted_input.chunk_by(|left, right| left == right) {
        let value = canonical_value::<F>(group[0]);
        permuted_input.push(value);
        permuted_table.push(value);
        for _ in 1..group.len() {
            permuted_input.push(value);
            permuted_table.push(canonical_value(leftover.next().ok_or_else(missing)?));
        }
    }
    if leftover.next().is_some() || permuted_input.len() != usable_rows {
        return Err(missing());
    }
    let input_pad = SecretPolynomial::new(random_values::<F, _>(rng, pad));
    permuted_input.extend_from_slice(&input_pad);
    let table_pad = SecretPolynomial::new(random_values::<F, _>(rng, pad));
    permuted_table.extend_from_slice(&table_pad);
    Ok((permuted_input.into_vec(), permuted_table.into_vec()))
}

/// Most-significant limb first, so array ordering equals field ordering.
fn canonical_key<F: PastaField>(value: &F) -> [u64; 4] {
    let mut limbs = value.to_canonical_limbs();
    limbs.reverse();
    limbs
}

/// Reconstructs keys produced solely from already valid field elements.
fn canonical_value<F: PastaField>(mut key: [u64; 4]) -> F {
    key.reverse();
    F::from_raw_reduced(key)
}

/// Only a singleton, unrotated fixed query is eligible. Inspect the full
/// public fixed column conservatively, including unused rows. This width never
/// depends on compressed inputs, theta, advice or the actual permuted scalars.
fn public_table_bits<F: PastaField>(
    descriptor: &crate::cs::descriptor_v2::ProtocolDescriptor,
    fixed: &[Vec<F>],
    lookup: usize,
    cancellation: Option<&CancellationToken>,
) -> Result<Option<usize>, ProverError> {
    use crate::cs::descriptor::ExprNodeV1;
    CancellationToken::checkpoint(cancellation)?;
    let Some(argument) = descriptor.lookups.get(lookup) else {
        return Ok(None);
    };
    let [table] = argument.tables.as_slice() else {
        return Ok(None);
    };
    if argument.inputs.len() != 1 {
        return Ok(None);
    }
    let [ExprNodeV1::Fixed(query)] = table.as_slice() else {
        return Ok(None);
    };
    let Some(query) = usize::try_from(*query)
        .ok()
        .and_then(|index| descriptor.fixed_queries.get(index))
    else {
        return Ok(None);
    };
    if query.rotation != 0 {
        return Ok(None);
    }
    let Some(column) = usize::try_from(query.column)
        .ok()
        .and_then(|index| fixed.get(index))
    else {
        return Ok(None);
    };
    let mut bits = 0;
    for chunk in column.chunks(1024) {
        CancellationToken::checkpoint(cancellation)?;
        for value in chunk {
            bits = bits.max(value.bit_length_vartime() as usize);
        }
    }
    CancellationToken::checkpoint(cancellation)?;
    // A full-width fixed table has no optimization to offer.
    Ok((bits < 255).then_some(bits))
}

/// Compresses, permutes (with `permutation`), blinds, commits and writes
/// every lookup's `A'` and `S'` (`BlindingScheduleV1` item 2).
///
/// # Errors
///
/// [`ProverError::LookupInputMissing`], or MSM, FFT and transcript errors.
#[allow(clippy::too_many_arguments)]
pub(super) fn commit_permuted<C, T, R, P>(
    params: &PinnedParams<C>,
    pk: &ProvingKey<C>,
    shape: &Shape,
    compiled: &CompiledExpressions<C::ScalarExt>,
    advice_values: &[Vec<C::ScalarExt>],
    instance_values: &[Vec<C::ScalarExt>],
    theta: C::ScalarExt,
    permutation: &mut P,
    rng: &mut R,
    transcript: &mut T,
    budget: MemoryBudget,
    cancellation: Option<&CancellationToken>,
) -> Result<Vec<Permuted<C::ScalarExt>>, ProverError>
where
    C: PastaCurve,
    T: TranscriptWrite<C>,
    R: RngCore,
    P: LookupPermutation<C::ScalarExt>,
{
    if shape.lookups == 0 {
        return Ok(Vec::new());
    }
    let compressed = compiled.compress_lookups_cancellable(
        pk.fixed_values(),
        advice_values,
        instance_values,
        theta,
        shape.n,
        cancellation,
    )?;
    let mut compressed = crate::secret::SecretLookupColumns::new(compressed);
    let tables = pk.commitment_tables();
    let mut permuted = Vec::with_capacity(compressed.len());
    for (lookup, (compressed_input, compressed_table)) in compressed.iter_mut().enumerate() {
        CancellationToken::checkpoint(cancellation)?;
        let compressed_input = SecretPolynomial::new(core::mem::take(compressed_input));
        let compressed_table = SecretPolynomial::new(core::mem::take(compressed_table));
        let (permuted_input, permuted_table) = permutation.permute(
            &compressed_input,
            &compressed_table,
            shape.usable_rows,
            shape.n,
            lookup,
            rng,
        )?;
        let permuted_input = SecretPolynomial::new(permuted_input);
        let permuted_table = SecretPolynomial::new(permuted_table);
        let input_blind = C::ScalarExt::random(&mut *rng);
        let table_blind = C::ScalarExt::random(&mut *rng);
        let public_bits = if P::PUBLIC_TABLE_BOUND {
            public_table_bits(
                pk.binding().descriptor(),
                pk.fixed_values(),
                lookup,
                cancellation,
            )?
        } else {
            None
        };
        let commit = |values: &[C::ScalarExt], blind: &C::ScalarExt| {
            public_bits.map_or_else(
                || {
                    tables.commit_lagrange_cancellable(
                        params.params(),
                        values,
                        blind,
                        Secrecy::Secret,
                        budget,
                        cancellation,
                    )
                },
                |bits| {
                    tables.commit_lagrange_bounded_prefix_cancellable(
                        params.params(),
                        values,
                        (shape.usable_rows, bits),
                        blind,
                        budget,
                        cancellation,
                    )
                },
            )
        };
        let input_commitment = commit(&permuted_input, &input_blind)?.to_affine();
        let table_commitment = commit(&permuted_table, &table_blind)?.to_affine();
        write_point(transcript, &input_commitment)?;
        write_point(transcript, &table_commitment)?;
        permuted.push(Permuted {
            compressed_input: compressed_input.into_vec(),
            compressed_table: compressed_table.into_vec(),
            input_values: permuted_input.into_vec(),
            table_values: permuted_table.into_vec(),
            input_blind,
            table_blind,
        });
    }
    Ok(permuted)
}

/// Builds, blinds, commits and writes every lookup's product `z`
/// (`BlindingScheduleV1` item 4).
///
/// # Errors
///
/// MSM, FFT and transcript errors.
#[allow(clippy::too_many_arguments)]
pub(super) fn commit_products<C, T, R>(
    params: &PinnedParams<C>,
    pk: &ProvingKey<C>,
    shape: &Shape,
    permuted: Vec<Permuted<C::ScalarExt>>,
    beta: C::ScalarExt,
    gamma: C::ScalarExt,
    rng: &mut R,
    transcript: &mut T,
    budget: MemoryBudget,
    cancellation: Option<&CancellationToken>,
) -> Result<Vec<Committed<C::ScalarExt>>, ProverError>
where
    C: PastaCurve,
    T: TranscriptWrite<C>,
    R: RngCore,
{
    let tables = pk.commitment_tables();
    let u = shape.usable_rows;
    let mut committed = Vec::with_capacity(permuted.len());
    for mut lookup in permuted {
        CancellationToken::checkpoint(cancellation)?;
        // The compressed values have no consumer after these numerators are
        // formed. Reuse their two allocations for the numerator and inverse
        // denominator columns instead of allocating fractions and a product.
        for ((numerator, denominator), (a, s)) in lookup.compressed_input[..u]
            .iter_mut()
            .zip(&mut lookup.compressed_table[..u])
            .zip(
                lookup.input_values[..u]
                    .iter()
                    .zip(&lookup.table_values[..u]),
            )
        {
            *numerator = (*numerator + beta) * (*denominator + gamma);
            *denominator = (*a + beta) * (*s + gamma);
        }
        invert_column_cancellable(&mut lookup.compressed_table[..u], cancellation)?;
        let mut product = SecretPolynomial::new(core::mem::take(&mut lookup.compressed_input));
        let mut running = C::ScalarExt::ONE;
        for (value, inverse) in product[..u].iter_mut().zip(&lookup.compressed_table[..u]) {
            let fraction = *inverse * *value;
            *value = running;
            running *= fraction;
        }
        product[u] = running;
        // No later phase needs this scratch, including the commitment MSM.
        // Move it into the wiping owner and release the allocation now; clearing
        // the vector would retain a whole field column through the MSM and FFTs.
        drop(SecretPolynomial::new(core::mem::take(
            &mut lookup.compressed_table,
        )));
        let random = SecretPolynomial::new(random_values::<C::ScalarExt, _>(
            rng,
            shape.blinding_factors,
        ));
        product[u + 1..].copy_from_slice(&random);
        let product_blind = C::ScalarExt::random(&mut *rng);
        let commitment = tables
            .commit_lagrange_cancellable(
                params.params(),
                &product,
                &product_blind,
                Secrecy::Secret,
                budget,
                cancellation,
            )?
            .to_affine();
        write_point(transcript, &commitment)?;
        pk.domain().ifft_cancellable(&mut product, cancellation)?;
        // The grand product is the last consumer of the evaluations. Move
        // their allocations into coefficient form instead of retaining an
        // extra pair of n-element vectors for every pending lookup.
        let mut input_poly = SecretPolynomial::new(core::mem::take(&mut lookup.input_values));
        let mut table_poly = SecretPolynomial::new(core::mem::take(&mut lookup.table_values));
        pk.domain()
            .ifft_cancellable(&mut input_poly, cancellation)?;
        pk.domain()
            .ifft_cancellable(&mut table_poly, cancellation)?;
        committed.push(Committed {
            input_poly: input_poly.into_vec(),
            input_blind: lookup.input_blind,
            table_poly: table_poly.into_vec(),
            table_blind: lookup.table_blind,
            product_poly: product.into_vec(),
            product_blind,
        });
    }
    Ok(committed)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use iroha_pasta::{Ep, Eq, Fp, Fq};
    use rand_chacha::ChaCha20Rng;
    use rand_core_06::{RngCore, SeedableRng};

    use super::*;
    use crate::{
        protocol::Protocol,
        test_circuits::{BUDGET, CHOICES, Lookups, setup},
        transcript::{Blake2bHash, TranscriptWriter},
    };

    fn values(raw: &[u64]) -> Vec<Fp> {
        raw.iter().map(|value| Fp::from(*value)).collect()
    }

    /// Independent field-ordered reference of the specified grouping and
    /// leftover-table rule, including the original padding stream order.
    fn reference_permutation<F: PastaField>(
        input: &[F],
        table: &[F],
        n: usize,
        rng: &mut ChaCha20Rng,
    ) -> Option<(Vec<F>, Vec<F>)> {
        let mut groups = BTreeMap::<F, usize>::new();
        for value in input {
            *groups.entry(*value).or_default() += 1;
        }
        let mut sorted = table.to_vec();
        sorted.sort_unstable();
        if groups
            .keys()
            .any(|value| sorted.binary_search(value).is_err())
        {
            return None;
        }
        let extra: Vec<F> = sorted
            .iter()
            .enumerate()
            .filter(|(i, value)| {
                (*i != 0 && sorted[i - 1] == **value) || !groups.contains_key(*value)
            })
            .map(|(_, value)| *value)
            .collect();
        let mut extra = extra.into_iter();
        let mut a = Vec::with_capacity(n);
        let mut s = Vec::with_capacity(n);
        for (value, count) in groups {
            a.push(value);
            s.push(value);
            for _ in 1..count {
                a.push(value);
                s.push(extra.next()?);
            }
        }
        assert!(extra.next().is_none());
        a.extend(random_values::<F, _>(rng, n - input.len()));
        s.extend(random_values::<F, _>(rng, n - input.len()));
        Some((a, s))
    }

    fn integer_key_parity<F: PastaField>() {
        let mut data = ChaCha20Rng::seed_from_u64(817);
        let mut edge = vec![F::ZERO, F::ONE, -F::ONE, F::from(1_u64 << 63)];
        edge.extend((0..125).map(|_| F::random(&mut data)));
        for value in &edge {
            assert_eq!(canonical_value::<F>(canonical_key(value)), *value);
            for other in &edge {
                assert_eq!(
                    canonical_key(value).cmp(&canonical_key(other)),
                    value.cmp(other)
                );
            }
        }
        for len in [0, 1, 7, 32, 129] {
            for seed in 0..12 {
                let table: Vec<F> = (0..len).map(|i| edge[i % edge.len()]).collect();
                let input: Vec<F> = (0..len)
                    .map(|_| table[usize::try_from(data.next_u32()).unwrap() % len])
                    .collect();
                let n = len + 6;
                let mut expected_rng = ChaCha20Rng::seed_from_u64(seed);
                let expected = reference_permutation(&input, &table, n, &mut expected_rng).unwrap();
                let mut actual_rng = ChaCha20Rng::seed_from_u64(seed);
                let actual = permute(&input, &table, len, n, 4, &mut actual_rng).unwrap();
                assert_eq!(actual, expected);
                assert_eq!(actual_rng.next_u64(), expected_rng.next_u64());
                if len > 0 {
                    let mut missing = input.clone();
                    missing[0] = F::from(19_337);
                    assert!(
                        reference_permutation(&missing, &table, n, &mut expected_rng).is_none()
                    );
                    assert!(matches!(
                        permute(&missing, &table, len, n, 4, &mut actual_rng),
                        Err(ProverError::LookupInputMissing { lookup: 4 })
                    ));
                }
            }
        }
    }

    #[test]
    fn canonical_integer_sort_preserves_both_field_permutations_and_padding() {
        integer_key_parity::<Fp>();
        integer_key_parity::<Fq>();
    }

    #[test]
    fn malformed_lookup_extents_reject_without_underflow() {
        let one = values(&[1]);
        let mut rng = ChaCha20Rng::seed_from_u64(9);
        for (input, table, usable, n) in [
            (one.as_slice(), one.as_slice(), 1, 0),
            (&[][..], one.as_slice(), 1, 2),
            (one.as_slice(), &[][..], 1, 2),
        ] {
            assert!(matches!(
                permute(input, table, usable, n, 7, &mut rng),
                Err(ProverError::LookupInputMissing { lookup: 7 })
            ));
        }
    }

    #[test]
    fn permutation_matches_the_vendored_layout() {
        // usable = 6, n = 8. Inputs {3, 1, 3, 2, 1, 3}; table {1, 2, 3, 4, 3, 5}.
        let input = values(&[3, 1, 3, 2, 1, 3, 0, 0]);
        let table = values(&[1, 2, 3, 4, 3, 5, 0, 0]);
        let mut rng = ChaCha20Rng::seed_from_u64(5);
        let (a, s) = permute(&input, &table, 6, 8, 0, &mut rng).expect("permute");
        // Groups 1 (x2), 2 (x1), 3 (x3); sorted table 1 2 3 3 4 5 gives the
        // leftovers [3, 4, 5].
        assert_eq!(&a[..6], values(&[1, 1, 2, 3, 3, 3]).as_slice());
        assert_eq!(&s[..6], values(&[1, 3, 2, 3, 4, 5]).as_slice());
        // A' and S' are permutations of the usable inputs and table values.
        let mut sorted_a = a[..6].to_vec();
        sorted_a.sort_unstable();
        let mut sorted_input = input[..6].to_vec();
        sorted_input.sort_unstable();
        assert_eq!(sorted_a, sorted_input);
        // Each A' row equals its predecessor or the S' row beside it.
        for row in 0..6 {
            assert!(a[row] == s[row] || (row > 0 && a[row] == a[row - 1]));
        }
        // Padding: A' rows first, then S' rows, from the same stream.
        let mut replay = ChaCha20Rng::seed_from_u64(5);
        let pads: Vec<Fp> = random_values(&mut replay, 4);
        assert_eq!(&a[6..], &pads[..2]);
        assert_eq!(&s[6..], &pads[2..]);
    }

    #[test]
    fn the_vendored_strategy_is_the_vendored_permutation() {
        let input = values(&[3, 1, 3, 2, 1, 3, 0, 0]);
        let table = values(&[1, 2, 3, 4, 3, 5, 0, 0]);
        let direct = permute(&input, &table, 6, 8, 0, &mut ChaCha20Rng::seed_from_u64(5));
        let strategy = VendoredPermutation.permute(
            &input,
            &table,
            6,
            8,
            0,
            &mut ChaCha20Rng::seed_from_u64(5),
        );
        assert_eq!(direct, strategy);
        assert!(direct.is_ok());
    }

    #[test]
    fn missing_inputs_are_prover_errors() {
        let input = values(&[1, 9, 0, 0]);
        let table = values(&[1, 2, 0, 0]);
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        assert_eq!(
            permute(&input, &table, 2, 4, 3, &mut rng).err(),
            Some(ProverError::LookupInputMissing { lookup: 3 })
        );
        assert_eq!(
            permute(&input, &table, 5, 4, 0, &mut rng).err(),
            Some(ProverError::LookupInputMissing { lookup: 0 })
        );
    }

    /// The consuming transition preserves the old interpolation, random
    /// stream and commitment while reusing the compressed-input and both
    /// permuted-evaluation allocations. The reference uses independent scalar
    /// inversions, including the specified zero-denominator behavior.
    fn check_product_consumes_evaluation_buffers<C: PastaCurve>(
        nontrivial: bool,
        zero_denominator: bool,
    ) {
        let circuit = Lookups {
            rows: 9,
            tamper: None,
            out_of_range: false,
            offset: 0,
        };
        let setup = setup::<C, _>(&circuit, CHOICES[0]);
        let pk = &setup.pk;
        let protocol = Protocol::new(pk.binding().descriptor()).expect("protocol");
        let shape = protocol.shape();
        let input_values: Vec<C::ScalarExt> = (0..shape.n)
            .map(|row| C::ScalarExt::from((row % 5) as u64))
            .collect();
        let table_values: Vec<C::ScalarExt> = (0..shape.n)
            .map(|row| C::ScalarExt::from((row % 7) as u64))
            .collect();
        let input_address = input_values.as_ptr();
        let table_address = table_values.as_ptr();
        let mut expected_input = input_values.clone();
        let mut expected_table = table_values.clone();
        pk.domain().ifft(&mut expected_input).expect("input ifft");
        pk.domain().ifft(&mut expected_table).expect("table ifft");
        let input_blind = C::ScalarExt::from(13);
        let table_blind = C::ScalarExt::from(17);
        let beta = if zero_denominator {
            -input_values[2]
        } else {
            C::ScalarExt::from(19)
        };
        let gamma = C::ScalarExt::from(23);
        let compressed_input: Vec<_> = input_values
            .iter()
            .enumerate()
            .map(|(row, value)| {
                if nontrivial {
                    *value + C::ScalarExt::from((row % 11 + 29) as u64)
                } else {
                    *value
                }
            })
            .collect();
        let compressed_table: Vec<_> = table_values
            .iter()
            .map(|value| {
                if nontrivial {
                    *value + C::ScalarExt::from(31)
                } else {
                    *value
                }
            })
            .collect();
        let product_address = compressed_input.as_ptr();
        let product_capacity = compressed_input.capacity();
        let mut expected_product = vec![C::ScalarExt::ONE];
        let mut running = C::ScalarExt::ONE;
        for row in 0..shape.usable_rows {
            let denominator = (input_values[row] + beta) * (table_values[row] + gamma);
            let numerator = (compressed_input[row] + beta) * (compressed_table[row] + gamma);
            running *= denominator.invert().unwrap_or(C::ScalarExt::ZERO) * numerator;
            expected_product.push(running);
        }
        let lookup = Permuted {
            compressed_input,
            compressed_table,
            input_values,
            table_values,
            input_blind,
            table_blind,
        };
        let mut rng = ChaCha20Rng::seed_from_u64(47);
        let mut replay = rng.clone();
        expected_product.extend(random_values::<C::ScalarExt, _>(
            &mut replay,
            shape.blinding_factors,
        ));
        let expected_blind = C::ScalarExt::random(&mut replay);
        let expected_commitment = pk
            .commitment_tables()
            .commit_lagrange(
                setup.params.params(),
                &expected_product,
                &expected_blind,
                Secrecy::Secret,
                BUDGET,
            )
            .expect("commit")
            .to_affine();
        let mut expected_transcript = TranscriptWriter::<C, _>::new(Blake2bHash::new());
        write_point(&mut expected_transcript, &expected_commitment).expect("write");
        pk.domain()
            .ifft(&mut expected_product)
            .expect("product ifft");
        let mut transcript = TranscriptWriter::<C, _>::new(Blake2bHash::new());
        let committed = commit_products(
            &setup.params,
            pk,
            shape,
            vec![lookup],
            beta,
            gamma,
            &mut rng,
            &mut transcript,
            BUDGET,
            None,
        )
        .expect("product");
        assert_eq!(committed.len(), 1);
        let committed = &committed[0];
        assert_eq!(committed.input_poly.as_ptr(), input_address);
        assert_eq!(committed.table_poly.as_ptr(), table_address);
        assert_eq!(committed.product_poly.as_ptr(), product_address);
        assert_eq!(committed.product_poly.capacity(), product_capacity);
        assert_eq!(committed.input_poly, expected_input);
        assert_eq!(committed.table_poly, expected_table);
        assert_eq!(committed.product_poly, expected_product);
        assert_eq!(committed.input_blind, input_blind);
        assert_eq!(committed.table_blind, table_blind);
        assert_eq!(committed.product_blind, expected_blind);
        assert_eq!(transcript.finish(), expected_transcript.finish());
        assert_eq!(rng.next_u64(), replay.next_u64());
    }

    #[test]
    fn product_consumes_evaluation_buffers_on_both_curves() {
        for nontrivial in [false, true] {
            for zero_denominator in [false, true] {
                check_product_consumes_evaluation_buffers::<Ep>(nontrivial, zero_denominator);
                check_product_consumes_evaluation_buffers::<Eq>(nontrivial, zero_denominator);
            }
        }
    }
}

#[cfg(test)]
#[path = "lookup/bounded_tests.rs"]
mod bounded_tests;
