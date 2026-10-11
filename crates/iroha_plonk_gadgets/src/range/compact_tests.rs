//! Compact fixed-pattern range binding, boundary and layout regressions.

use super::*;
use iroha_pasta::{Fp, Fq, PastaField};
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::{Column, ConstraintSystem, Instance},
    frontend::{Circuit, Error, Layouter, SimpleFloorPlanner, Value, synthesize},
};

#[derive(Clone)]
struct Range<F: PastaField> {
    value: Value<F>,
    bits: usize,
    compact: bool,
}
impl<F: PastaField> Circuit<F> for Range<F> {
    type Config = (RunningSumConfig, Column<Instance>);
    type FloorPlanner = SimpleFloorPlanner;
    type Params = bool;
    fn params(&self) -> bool {
        self.compact
    }
    fn without_witnesses(&self) -> Self {
        Self {
            value: Value::unknown(),
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        Self::configure_with_params(meta, true)
    }
    fn configure_with_params(meta: &mut ConstraintSystem<F>, compact: bool) -> Self::Config {
        let advice = meta.advice_column();
        let range = if compact {
            RunningSumConfig::configure_compact(meta, advice, LimbBits::new(7).unwrap())
        } else {
            RunningSumConfig::configure(meta, advice, LimbBits::new(7).unwrap())
        };
        let public = meta.instance_column(1);
        meta.enable_equality(public);
        (range, public)
    }
    fn synthesize(
        &self,
        (range, public): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let mut chip = RunningSumChip::new(range);
        chip.load_table(&mut layouter)?;
        let value = layouter.assign_region(
            || "compact range",
            |mut region| chip.witness_range_checked(&mut region, self.value, self.bits),
        )?;
        layouter.constrain_instance(value.cell(), public, 0)
    }
}
fn run<F: PastaField>() {
    for bits in [1, 7, 15, 16, 87, 105, 128, 252] {
        let limit = F::from(2).pow_vartime([bits as u64]);
        for (value, accepted) in [
            (F::ZERO, true),
            (limit - F::ONE, true),
            (limit, false),
            (-F::ONE, false),
        ] {
            for compact in [false, true] {
                let circuit = Range {
                    value: Value::known(value),
                    bits,
                    compact,
                };
                assert_eq!(
                    check_circuit(&circuit, 9, &[vec![value]], CheckMode::Strict)
                        .unwrap()
                        .is_satisfied(),
                    accepted
                );
            }
        }
    }
    let value = F::from_u128(u128::MAX);
    let circuit = Range {
        value: Value::known(value),
        bits: 128,
        compact: true,
    };
    let public = [vec![value]];
    let known = synthesize(&circuit, 9, Some(&public)).unwrap();
    let unknown = synthesize(&circuit.without_witnesses(), 9, None).unwrap();
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(known.tables.selectors(), unknown.tables.selectors());
    assert_eq!(known.tables.permutation(), unknown.tables.permutation());
    assert_eq!(
        known.tables.advice_assigned(),
        unknown.tables.advice_assigned()
    );
    assert_eq!(known.cs.lookups().len(), 1);
    assert_eq!(known.cs.degree(), 6);
    assert!(
        crate::tamper::undetected_tampers(&circuit, 9, &public)
            .unwrap()
            .is_empty()
    );
}
#[test]
fn compact_range_pattern_preserves_both_memberships_and_every_cell() {
    run::<Fp>();
    run::<Fq>();
}
