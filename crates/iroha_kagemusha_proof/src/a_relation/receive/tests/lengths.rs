//! Exhaustive joint-envelope boundary arithmetic using the production component.
//! Individual active-tape capacity and byte provenance remain separate owners.

use super::super::{MAX_OMEGA_RAW_BYTES, MAX_SIGMA_RAW_BYTES, joint_length_valid};
use ff::Field;
use iroha_pasta::Fp;
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::{Column, ConstraintSystem, Instance},
    frontend::{Circuit, Error, Layouter, SimpleFloorPlanner, Value, synthesize},
};
use iroha_plonk_gadgets::{
    GlueChip, GlueConfig, LimbBits, RunningSumChip, RunningSumConfig, UintChip,
};

const BATCH: usize = 96;
#[derive(Clone, Debug)]
struct Config {
    glue: GlueConfig,
    range: RunningSumConfig,
    output: Column<Instance>,
}
#[derive(Clone)]
struct Lengths {
    pairs: [[u32; 2]; BATCH],
    known: bool,
}
impl Circuit<Fp> for Lengths {
    type Config = Config;
    type Params = ();
    type FloorPlanner = SimpleFloorPlanner;
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Config {
        let advice = core::array::from_fn(|_| meta.advice_column());
        let constants = meta.fixed_column();
        let glue = GlueConfig::configure(meta, advice, constants);
        let column = meta.advice_column();
        let range = RunningSumConfig::configure(meta, column, LimbBits::new(9).unwrap());
        let output = meta.instance_column(BATCH);
        meta.enable_equality(output);
        Config {
            glue,
            range,
            output,
        }
    }
    fn synthesize(&self, config: Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        let mut glue = GlueChip::new(config.glue);
        let mut range = RunningSumChip::new(config.range);
        range.load_table(&mut layouter)?;
        let results = layouter.assign_region(
            || "fixed joint-envelope boundaries",
            |mut region| {
                let mut uint = UintChip::new(&mut glue, &mut range);
                self.pairs
                    .iter()
                    .map(|pair| {
                        let value = |v: u32| {
                            if self.known {
                                Value::known(u128::from(v))
                            } else {
                                Value::unknown()
                            }
                        };
                        let omega = uint.assign::<32>(&mut region, value(pair[0]))?;
                        let sigma = uint.assign::<32>(&mut region, value(pair[1]))?;
                        joint_length_valid(&mut uint, &mut region, &omega, &sigma)
                    })
                    .collect::<Result<Vec<_>, Error>>()
            },
        )?;
        for (row, result) in results.iter().enumerate() {
            layouter.constrain_instance(result.word().cell(), config.output, row)?;
        }
        Ok(())
    }
}
#[test]
fn every_joint_split_and_cap_plus_one_share_the_same_production_constraints() {
    let mut cases = Vec::new();
    cases.push(([0, 0], Fp::ONE));
    for sigma in 0..=u32::try_from(MAX_SIGMA_RAW_BYTES).unwrap() {
        let omega = u32::try_from(MAX_OMEGA_RAW_BYTES).unwrap() - sigma;
        cases.extend([
            ([omega, sigma], Fp::ONE),
            ([omega + 1, sigma], Fp::ZERO),
            ([omega, sigma + 1], Fp::ZERO),
        ]);
    }
    let reference = synthesize(
        &Lengths {
            pairs: [[0; 2]; BATCH],
            known: false,
        },
        14,
        None,
    )
    .unwrap();
    for (block, cases) in cases.chunks(BATCH).enumerate() {
        let mut circuit = Lengths {
            pairs: [[0; 2]; BATCH],
            known: true,
        };
        let mut expected = vec![Fp::ONE; BATCH];
        for (i, (pair, result)) in cases.iter().enumerate() {
            circuit.pairs[i] = *pair;
            expected[i] = *result;
        }
        let public = [expected];
        let actual = synthesize(&circuit, 14, Some(&public)).unwrap();
        assert_eq!(
            actual.tables.fixed(),
            reference.tables.fixed(),
            "block{block}"
        );
        assert_eq!(
            actual.tables.permutation(),
            reference.tables.permutation(),
            "block{block}"
        );
        let report =
            iroha_plonk::check::check(&actual.cs, &actual.tables, CheckMode::Strict).unwrap();
        assert!(
            report.is_satisfied(),
            "block{block}: {:?}",
            report.failures().first()
        );
        if block == 0 {
            let mut forged = public;
            forged[0][1] = Fp::ZERO;
            assert!(
                !check_circuit(&circuit, 14, &forged, CheckMode::Strict)
                    .unwrap()
                    .is_satisfied()
            );
        }
    }
}
