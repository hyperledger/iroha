//! Weighted catalog sums retain every middle/tail term and old narrow layouts.
use super::*;
use iroha_pasta::{Fp, Fq};
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::{Column, ConstraintSystem, Instance},
    frontend::{Circuit, Layouter, SimpleFloorPlanner, Value, synthesize},
};
use iroha_plonk_gadgets::GlueConfig;

#[derive(Clone)]
struct Sum {
    width: usize,
    known: bool,
    old_narrow_row: bool,
}
impl<F: PastaField> Circuit<F> for Sum {
    type Config = (GlueConfig, Column<Instance>);
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let columns = core::array::from_fn(|_| meta.advice_column());
        let constants = meta.fixed_column();
        let glue = GlueConfig::configure(meta, columns, constants);
        let instance = meta.instance_column(1);
        meta.enable_equality(instance);
        (glue, instance)
    }
    fn synthesize(
        &self,
        (config, instance): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let mut glue = GlueChip::new(config);
        let output = layouter.assign_region(
            || "catalog weighted sum",
            |mut region| {
                let words = (1..=self.width)
                    .map(|i| {
                        glue.witness(
                            &mut region,
                            if self.known {
                                Value::known(F::from(i as u64))
                            } else {
                                Value::unknown()
                            },
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let terms = words
                    .iter()
                    .enumerate()
                    .map(|(i, word)| (F::from((2 * i + 1) as u64), word))
                    .collect::<Vec<_>>();
                if self.old_narrow_row {
                    glue.linear(&mut region, &terms, F::ZERO)
                } else {
                    catalog_linear(&mut glue, &mut region, &terms)
                }
            },
        )?;
        layouter.constrain_instance(output.cell(), instance, 0)
    }
}

fn sums<F: PastaField>() {
    for width in [0, 1, 2, 3, 4, 5, 31, 32] {
        let circuit = Sum {
            width,
            known: true,
            old_narrow_row: false,
        };
        let expected = (1..=width)
            .map(|i| F::from((i * (2 * i - 1)) as u64))
            .fold(F::ZERO, |a, b| a + b);
        let public = [vec![expected]];
        assert!(
            check_circuit(&circuit, 7, &public, CheckMode::Strict)
                .unwrap()
                .is_satisfied()
        );
        if width > 0 {
            let middle = (width / 2 + 1) as u64;
            let dropped = [vec![expected - F::from(middle * (2 * middle - 1))]];
            assert!(
                !check_circuit(&circuit, 7, &dropped, CheckMode::Strict)
                    .unwrap()
                    .is_satisfied()
            );
        }
        if width <= 3 {
            let old = Sum {
                old_narrow_row: true,
                ..circuit.clone()
            };
            let new = synthesize(&circuit, 7, Some(&public)).unwrap();
            let old = synthesize(&old, 7, Some(&public)).unwrap();
            assert_eq!(new.tables.fixed(), old.tables.fixed());
            assert_eq!(new.tables.selectors(), old.tables.selectors());
            assert_eq!(new.tables.permutation(), old.tables.permutation());
            assert_eq!(new.tables.advice_assigned(), old.tables.advice_assigned());
        }
    }
}

#[test]
fn weighted_middle_and_tail_terms_and_narrow_source_are_exact_both_fields() {
    sums::<Fp>();
    sums::<Fq>();
}
