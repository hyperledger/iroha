//! Independent column inversions on the caller's worker pool.

use iroha_pasta::{PastaField, field::batch_invert_cancellable};
use rayon::prelude::*;

/// Invert each column entry, preserving zeros and the constant-time field
/// inversion path. Chunk boundaries depend only on the public column length
/// and worker count. Concurrent scratch lengths sum to the column length;
/// each chunk releases its scratch before returning.
#[cfg(test)]
pub(super) fn invert_column<F: PastaField>(values: &mut [F]) {
    invert_column_cancellable(values, None).unwrap();
}
pub(super) fn invert_column_cancellable<F: PastaField>(
    values: &mut [F],
    cancellation: Option<&iroha_pasta::CancellationToken>,
) -> Result<(), super::ProverError> {
    iroha_pasta::CancellationToken::checkpoint(cancellation)?;
    let workers = rayon::current_num_threads();
    if values.len() < 8192 || workers == 1 {
        batch_invert_cancellable(values, cancellation)?;
        return Ok(());
    }
    let chunk_len = values.len().div_ceil(workers).max(4096);
    values.par_chunks_mut(chunk_len).for_each(|chunk| {
        let _ = batch_invert_cancellable(chunk, cancellation);
    });
    iroha_pasta::CancellationToken::checkpoint(cancellation)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_pasta::{Fp, Fq};

    fn check<F: PastaField>() {
        for workers in [1, 4] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(workers)
                .build()
                .unwrap();
            for len in [0_usize, 1, 8191, 8192, 65_537] {
                let mut values: Vec<F> = (0..len)
                    .map(|i| {
                        if i % 11 == 0 {
                            F::ZERO
                        } else {
                            F::from(i as u64)
                        }
                    })
                    .collect();
                let original = values.clone();
                pool.install(|| invert_column(&mut values));
                for (value, original) in values.iter().zip(original) {
                    if original == F::ZERO {
                        assert_eq!(*value, F::ZERO);
                    } else {
                        assert_eq!(*value * original, F::ONE);
                    }
                }
                values.fill(F::ZERO);
                pool.install(|| invert_column(&mut values));
                assert!(values.iter().all(|value| *value == F::ZERO));
            }
        }
    }

    #[test]
    fn column_inversion_preserves_zeros_and_inverses_on_both_fields() {
        check::<Fp>();
        check::<Fq>();
    }
}
