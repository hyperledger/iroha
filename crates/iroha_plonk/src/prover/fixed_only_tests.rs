//! Actual-proof checks for zero-transform and exactly bounded coset workspace.

use super::*;
use crate::{
    cs::{Column, ConstraintSystem, Expression, Fixed, Rotation},
    frontend::{Circuit, Error, Layouter, SimpleFloorPlanner},
    keys::{CosetCachePolicy, KeygenConfigV2, keygen_pk_v2},
};

/// A nonconstant fixed boolean polynomial with no witness, equality or lookup
/// columns. Its eager key needs no owned quotient FFT buffers at all.
#[derive(Clone, Copy)]
struct FixedBoolean;

impl<F: PastaField> Circuit<F> for FixedBoolean {
    type Config = Column<Fixed>;
    type Params = Vec<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        *self
    }

    fn configure(cs: &mut ConstraintSystem<F>) -> Self::Config {
        let fixed = cs.fixed_column();
        cs.create_gate("fixed boolean", |cells| {
            let value = cells.query_fixed(fixed, Rotation::cur());
            [value.clone() * (value - Expression::Constant(F::ONE))]
        });
        fixed
    }

    fn synthesize(&self, fixed: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_region(
            || "one fixed boolean",
            |mut region| {
                region.assign_fixed(fixed, 0, F::ONE)?;
                Ok(())
            },
        )
    }
}

#[test]
fn fixed_only_proof_has_zero_eager_workspace_and_exact_on_demand_bound() {
    fn check<C: PastaCurve>()
    where
        C::ScalarExt: PoseidonField,
        C::Base: PoseidonField,
    {
        let params = PinnedParams::<C>::derive(K).unwrap();
        let mut previous_proof = None;
        for policy in [CosetCachePolicy::Eager, CosetCachePolicy::OnDemand] {
            let mut config = KeygenConfigV2::pipa_r(Vec::new());
            config.coset_cache = policy;
            let pk = keygen_pk_v2(&params, &FixedBoolean, &config).unwrap();
            let setup = Setup {
                params: params.clone(),
                pk,
            };
            let witness = Witness::from_circuit(&setup.pk, &FixedBoolean, &[]).unwrap();
            let protocol = Protocol::new(setup.pk.binding().descriptor()).unwrap();
            assert_eq!(protocol.shape().num_fixed, 1);
            assert_eq!(protocol.shape().num_advice, 0);
            assert_eq!(protocol.shape().num_instance, 0);
            assert_eq!(protocol.shape().permutation_columns, 0);
            assert_eq!(protocol.shape().lookups, 0);
            // This explicit count is a property of this actual circuit: either
            // borrow the fixed coset, or retain one fixed column and one plan.
            let expected = match policy {
                CosetCachePolicy::Eager => 0,
                CosetCachePolicy::OnDemand => 2 * (1usize << K) * size_of::<C::ScalarExt>(),
            };
            assert_eq!(
                quotient::workspace_elements(&setup.pk, &protocol).unwrap()
                    * size_of::<C::ScalarExt>(),
                expected
            );
            let reference = create_proof(
                &setup.params,
                &setup.pk,
                &witness,
                ProverRandomness::fixed_seed_for_tests([117; 32]),
                ProverConfig::default(),
            )
            .unwrap();
            if let Some(prior) = previous_proof.replace(reference.clone()) {
                assert_eq!(reference, prior, "cache policy must not change proof bytes");
            }
            let mut workspace = QuotientWorkspace::new(expected);
            for workers in [1, 4, 1] {
                let pool = rayon::ThreadPoolBuilder::new()
                    .num_threads(workers)
                    .build()
                    .unwrap();
                let owned = Witness::from_circuit(&setup.pk, &FixedBoolean, &[]).unwrap();
                let result = pool
                    .install(|| {
                        create_proof_owned_with_workspace(
                            &setup.params,
                            &setup.pk,
                            owned,
                            ProverRandomness::fixed_seed_for_tests([117; 32]),
                            ProverConfig::default(),
                            &mut workspace,
                        )
                    })
                    .unwrap();
                assert_eq!(result.proof, reference);
                assert_eq!(result.opening.decide(&setup.params, BUDGET), Ok(()));
                assert_eq!(setup.verify(&[], &result.proof), Ok(()));
                assert_eq!(workspace.allocated_bytes(), expected);
                assert!(workspace.is_zeroized());
            }
            if expected > 0 {
                let mut short = QuotientWorkspace::new(expected - 1);
                let owned = Witness::from_circuit(&setup.pk, &FixedBoolean, &[]).unwrap();
                assert!(matches!(
                    create_proof_owned_with_workspace(
                        &setup.params,
                        &setup.pk,
                        owned,
                        ProverRandomness::fixed_seed_for_tests([117; 32]),
                        ProverConfig::default(),
                        &mut short,
                    ),
                    Err(ProverError::Workspace(WorkspaceError::Limit { .. }))
                ));
                assert_eq!(short.allocated_bytes(), 0);
            }
        }
    }
    check::<Ep>();
    check::<Eq>();
}
