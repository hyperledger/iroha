//! Carried scheme scope, fixed provider policy and source-layout regression.
//!
//! This checks the scope component only; no signature-Q or operation proof is admitted.

use super::*;
use crate::{
    operation_relation::state::rest_index,
    witness::{CORE_FIELDS, REST_FIELDS, core_index},
};
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::{Column, ConstraintSystem, Instance},
    frontend::{Circuit, Layouter, SimpleFloorPlanner, Value, synthesize},
};
use iroha_plonk_recursion::verifier::VerifierConfig;

#[derive(Clone)]
struct ScopeCircuit {
    scheme: [Fp; 2],
    known: bool,
}
#[derive(Clone, Debug)]
struct Config {
    verifier: VerifierConfig<Ep>,
    public: Column<Instance>,
}
impl ScopeCircuit {
    fn instance(&self) -> Vec<Fp> {
        vec![self.scheme[0], self.scheme[1], Fp::from(11), Fp::from(13)]
    }
    fn value(&self, v: Fp) -> Value<Fp> {
        if self.known {
            Value::known(v)
        } else {
            Value::unknown()
        }
    }
}
impl Circuit<Fp> for ScopeCircuit {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Config {
        let public = meta.instance_column(4);
        meta.enable_equality(public);
        Config {
            verifier: VerifierConfig::configure_serialized_foreign_tagged(meta, 3).unwrap(),
            public,
        }
    }
    fn synthesize(&self, config: Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        let mut chip = VerifierChip::new(config.verifier);
        chip.load_tables(&mut layouter)?;
        let words = layouter.assign_region(
            || "carried own scope",
            |mut region| {
                let mut core = [Fp::ZERO; CORE_FIELDS];
                for i in [
                    core_index::LIFECYCLE,
                    core_index::ASSET,
                    core_index::WALLET,
                    core_index::CREDENTIAL,
                    core_index::CONSUMED_CREDIT_ROOT,
                    core_index::PENDING_OUTGOING_ROOT,
                    core_index::LOAD_REDEEM_ROOT,
                    core_index::FEE_CLAIM_ROOT,
                    core_index::QUOTA_USAGE_ROOT,
                    core_index::STATE_NONCE,
                ] {
                    core[i] = Fp::ONE;
                }
                core[core_index::SCHEME..=core_index::SCHEME + 1].copy_from_slice(&self.scheme);
                let mut rest = [Fp::ZERO; REST_FIELDS];
                rest[rest_index::BLACKLIST_HISTORY] = Fp::ONE;
                let core = chip
                    .uint()
                    .glue()
                    .witnesses(&mut region, &core.map(|v| self.value(v)))?
                    .try_into()
                    .map_err(|_| Error::Synthesis)?;
                let rest = chip
                    .uint()
                    .glue()
                    .witnesses(&mut region, &rest.map(|v| self.value(v)))?
                    .try_into()
                    .map_err(|_| Error::Synthesis)?;
                let state =
                    StateCells::constrain_with_verifier(&mut chip, &mut region, &core, &rest)?;
                let policy = OwnPolicy::new([11, 13], Affine::GENERATOR)?;
                let scope = policy.scope(&mut chip, &mut region, &state)?;
                Ok(scope
                    .scheme
                    .into_iter()
                    .chain(scope.provider)
                    .collect::<Vec<_>>())
            },
        )?;
        for (i, word) in words.iter().enumerate() {
            layouter.constrain_instance(word.cell(), config.public, i)?;
        }
        Ok(())
    }
}

#[test]
fn carried_scheme_does_not_change_fixed_source_and_rejects_foreign_public_scope() {
    let first = ScopeCircuit {
        scheme: [Fp::from(17), Fp::from(19)],
        known: true,
    };
    let second = ScopeCircuit {
        scheme: [Fp::from(23), Fp::from(29)],
        known: true,
    };
    for circuit in [&first, &second] {
        let public = [circuit.instance()];
        assert!(
            check_circuit(circuit, 16, &public, CheckMode::Strict)
                .unwrap()
                .is_satisfied()
        );
        for i in 0..4 {
            let mut changed = public.clone();
            changed[0][i] += Fp::ONE;
            assert!(
                !check_circuit(circuit, 16, &changed, CheckMode::Strict)
                    .unwrap()
                    .is_satisfied()
            );
        }
    }
    let known = synthesize(&first, 16, None).unwrap();
    for circuit in [second, first.without_witnesses()] {
        let other = synthesize(&circuit, 16, None).unwrap();
        assert_eq!(known.tables.fixed(), other.tables.fixed());
        assert_eq!(known.tables.permutation(), other.tables.permutation());
        assert_eq!(
            known.tables.advice_assigned(),
            other.tables.advice_assigned()
        );
    }
}

#[test]
fn policy_keeps_provider_and_root_validation_without_a_scheme_constant() {
    assert!(OwnPolicy::new([11, 13], Affine::GENERATOR).is_ok());
    assert!(OwnPolicy::new([0; 2], Affine::GENERATOR).is_err());
    assert!(
        OwnPolicy::new(
            [11, 13],
            Affine {
                x: [0; 4],
                y: [0; 4]
            }
        )
        .is_err()
    );
}
