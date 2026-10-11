//! Per-proof cancellation and exact retry across the complete prover pipeline.

use super::*;
use crate::protocol::ConstraintTerm;
use crate::test_circuits::{Arithmetic, CHOICES, setup};
use iroha_pasta::{CancellationToken, Ep, Eq};

struct CancelInQuotient<'a>(&'a CancellationToken);
impl ConstraintFilter for CancelInQuotient<'_> {
    fn keeps(&self, _: ConstraintTerm) -> bool {
        self.0.cancel();
        true
    }
}

fn cancellation_resumes_identically<C: PastaCurve>()
where
    C::ScalarExt: PoseidonField,
    C::Base: PoseidonField,
{
    let circuit = Arithmetic {
        start: 3,
        rows: 12,
        tamper: None,
    };
    let setup = setup::<C, _>(&circuit, CHOICES[1]);
    let instances = circuit.instances::<C::ScalarExt>();
    let witness = || Witness::from_circuit(&setup.pk, &circuit, &instances).unwrap();
    let randomness = || ProverRandomness::fixed_seed_for_tests([197; 32]);
    let expected = create_proof_owned(
        &setup.params,
        &setup.pk,
        witness(),
        randomness(),
        ProverConfig::default(),
    )
    .unwrap();
    for workers in [1, 4] {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(workers)
            .build()
            .unwrap();
        let token = CancellationToken::new();
        let config = ProverConfig {
            msm_budget: MemoryBudget::DEFAULT,
            cancellation: Some(&token),
        };
        let mut workspace = QuotientWorkspace::new(8 << 20);
        let result = pool.install(|| {
            prove_output(
                &setup.params,
                &setup.pk,
                WitnessInput::Owned(witness()),
                randomness(),
                config,
                Mode {
                    oracle: false,
                    transcript_repr: *setup.pk.vk().transcript_repr(),
                },
                &mut lookup::VendoredPermutation,
                &CancelInQuotient(&token),
                Some(&mut workspace),
            )
        });
        assert!(
            matches!(result, Err(ProverError::Cancelled)),
            "must report cancellation, not an invalid proof: {result:?}"
        );
        assert!(
            workspace.allocated_bytes() > 0,
            "cancellation occurred after workspace admission"
        );
        assert!(
            workspace.is_zeroized(),
            "lease zeroized every used/unused column before return"
        );
        assert_eq!(
            pool.install(|| create_proof_owned(
                &setup.params,
                &setup.pk,
                witness(),
                randomness(),
                config
            )),
            Err(ProverError::Cancelled)
        );
        let fresh = CancellationToken::new();
        let config = ProverConfig {
            msm_budget: MemoryBudget::DEFAULT,
            cancellation: Some(&fresh),
        };
        let resumed = pool
            .install(|| {
                create_proof_owned_with_workspace(
                    &setup.params,
                    &setup.pk,
                    witness(),
                    randomness(),
                    config,
                    &mut workspace,
                )
            })
            .unwrap();
        assert_eq!(
            resumed.proof, expected,
            "cancellation/retry cannot change seeded proof bytes"
        );
        assert_eq!(setup.verify(&instances, &resumed.proof), Ok(()));
        assert!(workspace.is_zeroized());
    }
}

#[test]
fn prover_cancellation_resumes_identically() {
    cancellation_resumes_identically::<Ep>();
    cancellation_resumes_identically::<Eq>();
}

#[test]
fn cancellation_errors_stay_distinct_through_every_prover_layer() {
    let cancelled = iroha_pasta::Cancelled;
    assert_eq!(ProverError::from(cancelled), ProverError::Cancelled);
    assert_eq!(
        ProverError::from(MsmError::Cancelled),
        ProverError::Cancelled
    );
    assert_eq!(
        ProverError::from(FftError::Cancelled),
        ProverError::Cancelled
    );
    assert_eq!(
        ProverError::from(KeyError::Cancelled),
        ProverError::Cancelled
    );
    let ipa = crate::pcs::ipa::IpaError::from(MsmError::Cancelled);
    assert_eq!(ipa, crate::pcs::ipa::IpaError::Cancelled);
    let multiopen = MultiopenError::from(ipa);
    assert_eq!(multiopen, MultiopenError::Cancelled);
    assert_eq!(ProverError::from(multiopen), ProverError::Cancelled);
    assert_ne!(
        ProverError::from(MsmError::TooLarge { n: usize::MAX }),
        ProverError::Cancelled
    );
}
