//! Bounded-prefix commitments retain the original full-width padding and blind.

use super::*;
use ff::Field;
use iroha_pasta::{Ep, Eq};
use rand_chacha::ChaCha20Rng;
use rand_core_06::SeedableRng;

fn parity<C: PastaCurve>() {
    let params = ParamsIpa::<C>::new(6).unwrap();
    let mut rng = ChaCha20Rng::from_seed([27; 32]);
    let blind = C::ScalarExt::random(&mut rng);
    for prefix in [0, 1, 8, 9, 57, 64] {
        let values = (0..64)
            .map(|i| {
                if i < prefix {
                    C::ScalarExt::from((i as u64 * 997) & 32767)
                } else {
                    C::ScalarExt::random(&mut rng)
                }
            })
            .collect::<Vec<_>>();
        if prefix < 64 {
            assert!(values[prefix].bit_length_vartime() > 15);
        }
        let reference = commit_lagrange(
            &params,
            &values,
            &blind,
            Secrecy::Secret,
            MemoryBudget::DEFAULT,
        )
        .unwrap();
        for tables in [
            CommitmentTables::none(),
            CommitmentTables::build(&params, MemoryBudget::DEFAULT),
        ] {
            for threads in [1, 4] {
                let pool = rayon::ThreadPoolBuilder::new()
                    .num_threads(threads)
                    .build()
                    .unwrap();
                let result = pool
                    .install(|| {
                        tables.commit_lagrange_bounded_prefix_cancellable(
                            &params,
                            &values,
                            (prefix, 15),
                            &blind,
                            MemoryBudget::DEFAULT,
                            None,
                        )
                    })
                    .unwrap();
                assert_eq!(result.to_affine(), reference.to_affine());
            }
        }
    }
    let empty = CommitmentTables::none()
        .commit_lagrange_bounded_prefix_cancellable(
            &params,
            &[],
            (0, 0),
            &blind,
            MemoryBudget::new(0),
            None,
        )
        .unwrap();
    assert_eq!(empty, params.w().to_curve() * blind);
}

#[test]
fn bounded_commitments_preserve_random_padding_and_blinds_on_both_curves() {
    parity::<Ep>();
    parity::<Eq>();
}

#[test]
fn invalid_prefix_is_rejected_before_tables_small_inputs_or_budget_fallback() {
    let params = ParamsIpa::<Ep>::new(4).unwrap();
    let blind = iroha_pasta::Fq::ONE;
    let values = [iroha_pasta::Fq::from(32768); 16];
    for tables in [
        CommitmentTables::none(),
        CommitmentTables::build(&params, MemoryBudget::DEFAULT),
    ] {
        for count in [1, 8, 16] {
            for budget in [MemoryBudget::new(0), MemoryBudget::DEFAULT] {
                assert_eq!(
                    tables.commit_lagrange_bounded_prefix_cancellable(
                        &params,
                        &values[..count],
                        (count, 15),
                        &blind,
                        budget,
                        None
                    ),
                    Err(MsmError::ScalarBound)
                );
            }
        }
        assert!(matches!(
            tables.commit_lagrange_bounded_prefix_cancellable(
                &params,
                &values,
                (17, 15),
                &blind,
                MemoryBudget::DEFAULT,
                None
            ),
            Err(MsmError::LengthMismatch(_))
        ));
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        assert_eq!(
            tables.commit_lagrange_bounded_prefix_cancellable(
                &params,
                &values,
                (0, 0),
                &blind,
                MemoryBudget::DEFAULT,
                Some(&cancellation)
            ),
            Err(MsmError::Cancelled)
        );
    }
    let too_long = [iroha_pasta::Fq::ZERO; 17];
    assert!(matches!(
        CommitmentTables::none().commit_lagrange_bounded_prefix_cancellable(
            &params,
            &too_long,
            (17, 0),
            &blind,
            MemoryBudget::DEFAULT,
            None
        ),
        Err(MsmError::LengthMismatch(_))
    ));
}
