//! The permutation grand products (spec section 2 "Permutation", section 7
//! row 3, `BlindingScheduleV1` item 3).
//!
//! The equality columns are split into sets of `d - 2` columns. For set `s`
//! the prover builds
//!
//! ```text
//! z_s(omega^0) = z_{s-1}(omega^u)   (1 for the first set)
//! z_s(omega^(i+1)) = z_s(omega^i) prod_j (v_j(omega^i) + beta DELTA^j omega^i + gamma)
//!                                  / (v_j(omega^i) + beta sigma_j(omega^i) + gamma)
//! ```
//!
//! over every row, where `j` is the global equality index, then overwrites
//! rows `n-b..n` with random values, draws its blind and writes its
//! commitment. The values `v_j` are the advice columns with their blinding
//! rows, the fixed columns and the zero-padded instance columns.

use crate::secret::SecretPolynomial;
use ff::{Field, PrimeField};
use iroha_pasta::CancellationToken;
use iroha_pasta::{PastaCurve, msm::MemoryBudget};
use rand_core_06::RngCore;
use rayon::prelude::*;

use super::{ProverError, batch::invert_column_cancellable, random_values, write_point};
use crate::{
    cs::descriptor::ColumnKindV1,
    keys::ProvingKey,
    pcs::ipa::{PinnedParams, commit::Secrecy},
    protocol::Protocol,
    transcript::TranscriptWrite,
};

/// Rows per parallel task; the result does not depend on it.
const ROWS_PER_TASK: usize = 1 << 10;

/// A committed permutation set.
pub(super) struct ProductSet<F: iroha_pasta::PastaField> {
    /// `z_s` in coefficient form.
    pub(super) poly: Vec<F>,
    /// Its blind.
    pub(super) blind: F,
}
impl<F: iroha_pasta::PastaField> Drop for ProductSet<F> {
    fn drop(&mut self) {
        self.poly.iter_mut().for_each(crate::secret::wipe_one);
        self.blind.zeroize();
    }
}

/// The values of one equality column in evaluation form.
fn column_values<'a, F>(
    kind: ColumnKindV1,
    column: usize,
    fixed: &'a [Vec<F>],
    advice: &'a [Vec<F>],
    instance: &'a [Vec<F>],
) -> Option<&'a [F]> {
    match kind {
        ColumnKindV1::Advice => advice.get(column),
        ColumnKindV1::Fixed => fixed.get(column),
        ColumnKindV1::Instance => instance.get(column),
    }
    .map(Vec::as_slice)
}

/// Builds, blinds, commits and writes every permutation set's product.
///
/// # Errors
///
/// [`ProverError::Key`] for a missing column, or MSM, FFT and transcript
/// errors.
#[allow(clippy::too_many_arguments)]
pub(super) fn commit<C, T, R>(
    params: &PinnedParams<C>,
    pk: &ProvingKey<C>,
    protocol: &Protocol,
    advice: &[Vec<C::ScalarExt>],
    instance: &[Vec<C::ScalarExt>],
    beta: C::ScalarExt,
    gamma: C::ScalarExt,
    rng: &mut R,
    transcript: &mut T,
    budget: MemoryBudget,
    cancellation: Option<&CancellationToken>,
) -> Result<Vec<ProductSet<C::ScalarExt>>, ProverError>
where
    C: PastaCurve,
    T: TranscriptWrite<C>,
    R: RngCore,
{
    let shape = protocol.shape();
    let n = shape.n;
    let omega = pk.domain().omega();
    let tables = pk.commitment_tables();
    let sigma_values = pk.permutation_values();
    let columns = protocol.permutation_columns();
    let mut sets = Vec::with_capacity(shape.permutation_sets);
    let mut last = C::ScalarExt::ONE;
    let mut delta_power = C::ScalarExt::ONE;
    for (set_columns, set_sigma) in columns
        .chunks(shape.chunk_len)
        .zip(sigma_values.chunks(shape.chunk_len))
    {
        let values = set_columns
            .iter()
            .map(|column| {
                column_values(
                    column.kind,
                    column.column,
                    pk.fixed_values(),
                    advice,
                    instance,
                )
                .ok_or(ProverError::Key(crate::keys::KeyError::CosetIndex))
            })
            .collect::<Result<Vec<_>, _>>()?;
        // Denominators prod_j (v_j + beta sigma_j + gamma).
        let mut modified = SecretPolynomial::new(vec![C::ScalarExt::ONE; n]);
        modified
            .par_chunks_mut(ROWS_PER_TASK)
            .enumerate()
            .for_each(|(task, out)| {
                if CancellationToken::checkpoint(cancellation).is_err() {
                    return;
                }
                let start = task * ROWS_PER_TASK;
                for (offset, value) in out.iter_mut().enumerate() {
                    let row = start + offset;
                    for (column, sigma) in values.iter().zip(set_sigma) {
                        *value *= column[row] + beta * sigma[row] + gamma;
                    }
                }
            });
        CancellationToken::checkpoint(cancellation)?;
        invert_column_cancellable(&mut modified, cancellation)?;
        // Numerators prod_j (v_j + beta DELTA^j omega^i + gamma).
        let set_delta = delta_power;
        modified
            .par_chunks_mut(ROWS_PER_TASK)
            .enumerate()
            .for_each(|(task, out)| {
                if CancellationToken::checkpoint(cancellation).is_err() {
                    return;
                }
                let start = task * ROWS_PER_TASK;
                let start_power = omega.pow_vartime([start as u64]);
                let mut column_delta = set_delta;
                for column in &values {
                    let mut delta_omega = column_delta * start_power;
                    for (offset, value) in out.iter_mut().enumerate() {
                        *value *= column[start + offset] + delta_omega * beta + gamma;
                        delta_omega *= omega;
                    }
                    column_delta *= <C::ScalarExt as PrimeField>::DELTA;
                }
            });
        CancellationToken::checkpoint(cancellation)?;
        for _ in set_columns {
            delta_power *= <C::ScalarExt as PrimeField>::DELTA;
        }
        let mut product = SecretPolynomial::new(Vec::with_capacity(n));
        let mut running = last;
        product.push(running);
        for fraction in &modified[..n - 1] {
            running *= fraction;
            product.push(running);
        }
        let first_blinding_row = n - shape.blinding_factors;
        let random = SecretPolynomial::new(random_values::<C::ScalarExt, _>(
            rng,
            shape.blinding_factors,
        ));
        product[first_blinding_row..].copy_from_slice(&random);
        last = product[shape.usable_rows];
        let blind = C::ScalarExt::random(&mut *rng);
        let commitment = tables
            .commit_lagrange_cancellable(
                params.params(),
                &product,
                &blind,
                Secrecy::Secret,
                budget,
                cancellation,
            )?
            .to_affine();
        write_point(transcript, &commitment)?;
        pk.domain().ifft_cancellable(&mut product, cancellation)?;
        sets.push(ProductSet {
            poly: product.into_vec(),
            blind,
        });
    }
    Ok(sets)
}

#[cfg(test)]
mod tests {
    use iroha_pasta::Fp;

    use super::*;

    #[test]
    fn column_values_select_by_kind() {
        let fixed = vec![vec![Fp::from(1)]];
        let advice = vec![vec![Fp::from(2)], vec![Fp::from(3)]];
        let instance = vec![vec![Fp::from(4)]];
        let get = |kind, column| column_values(kind, column, &fixed, &advice, &instance);
        assert_eq!(get(ColumnKindV1::Fixed, 0), Some([Fp::from(1)].as_slice()));
        assert_eq!(get(ColumnKindV1::Advice, 1), Some([Fp::from(3)].as_slice()));
        assert_eq!(
            get(ColumnKindV1::Instance, 0),
            Some([Fp::from(4)].as_slice())
        );
        assert_eq!(get(ColumnKindV1::Advice, 2), None);
    }
}
