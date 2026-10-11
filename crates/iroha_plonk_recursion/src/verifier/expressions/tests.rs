//! Direct inverse and exact-index cache attacks for the factored Lagrange sum.

use super::*;
use iroha_pasta::{Ep, Eq, PastaField};
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::{Column, ConstraintSystem, Instance},
    frontend::{Cell, Circuit, Layouter, SimpleFloorPlanner, Value, synthesize},
};
use iroha_plonk_gadgets::tamper::{Tamper, check_tampered};
use std::{cell::RefCell, rc::Rc};

#[derive(Clone)]
struct Probe<C: PastaCurve> {
    x: C::ScalarExt,
    index: usize,
    known: bool,
    inverse_cells: Rc<RefCell<Vec<Cell>>>,
}
impl<C: PastaCurve> Circuit<C::Base> for Probe<C> {
    type Config = (VerifierConfig<C>, Column<Instance>);
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn configure(meta: &mut ConstraintSystem<C::Base>) -> Self::Config {
        let verifier = VerifierConfig::configure(meta);
        let public = meta.instance_column(5);
        meta.enable_equality(public);
        (verifier, public)
    }
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn synthesize(
        &self,
        (config, public): Self::Config,
        mut layouter: impl Layouter<C::Base>,
    ) -> Result<(), Error> {
        let mut chip = VerifierChip::<C>::new(config);
        chip.load_tables(&mut layouter)?;
        let outputs = layouter.assign_region(
            || "factored Lagrange inverses",
            |mut region| {
                let witness = if self.known {
                    Value::known(self.x.to_canonical_limbs())
                } else {
                    Value::unknown()
                };
                let x = chip.arithmetic.ff.witness_canonical(
                    &mut region,
                    Arithmetic::<C>::modulus(),
                    witness,
                )?;
                let mut valid = chip.glue.boolean(&mut region, Value::known(true))?;
                chip.glue
                    .enforce_constant(&mut region, valid.word(), C::Base::ONE)?;
                let one = chip.constant(&mut region, C::ScalarExt::ONE)?;
                let xn = chip.pow(&mut region, &x, 64)?;
                let denominator = chip.sub(&mut region, &xn, &one)?;
                let (vanishing, guard) = chip.arithmetic.inverse(
                    &mut UintChip::new(&mut chip.glue, &mut chip.range),
                    &mut region,
                    &denominator,
                )?;
                chip.combine(&mut region, &mut valid, &guard)?;
                let mut cache = std::collections::BTreeMap::new();
                let weight =
                    chip.lagrange_weight(&mut region, 6, self.index, &x, &guard, &mut cache)?;
                let row = chip.arithmetic.ff.next_row();
                let again =
                    chip.lagrange_weight(&mut region, 6, self.index, &x, &guard, &mut cache)?;
                assert_eq!(row, chip.arithmetic.ff.next_row());
                assert_eq!(
                    weight.limbs().each_ref().map(Word::cell),
                    again.limbs().each_ref().map(Word::cell)
                );
                *self.inverse_cells.borrow_mut() = vanishing
                    .limbs()
                    .iter()
                    .chain(weight.limbs())
                    .map(Word::cell)
                    .chain([guard.cell(), valid.cell()])
                    .collect();
                let vanishing = chip.export(&mut region, &vanishing)?;
                let weight = chip.export(&mut region, &weight)?;
                Ok([
                    vanishing.lo().cell(),
                    vanishing.hi().cell(),
                    weight.lo().cell(),
                    weight.hi().cell(),
                    valid.cell(),
                ])
            },
        )?;
        for (row, cell) in outputs.into_iter().enumerate() {
            layouter.constrain_instance(cell, public, row)?;
        }
        Ok(())
    }
}
fn cases<C: PastaCurve>() {
    let omega = iroha_plonk::protocol::omega::<C::ScalarExt>(6).unwrap();
    for (x, index) in [
        (C::ScalarExt::ONE, 0),
        (C::ScalarExt::ONE, 63),
        (C::ScalarExt::from(2), 0),
        (C::ScalarExt::from(2), 63),
        (omega.pow_vartime([7]), 7),
        (omega.pow_vartime([7]), 0),
    ] {
        let circuit = Probe::<C> {
            x,
            index,
            known: true,
            inverse_cells: Rc::default(),
        };
        let vanishing = x.pow_vartime([64]) - C::ScalarExt::ONE;
        let power = omega.pow_vartime([index as u64]);
        let denominator = x - power;
        let valid = !bool::from(vanishing.is_zero());
        let weight = if valid {
            power * denominator.invert().unwrap()
        } else {
            C::ScalarExt::ZERO
        };
        let limbs = |value: C::ScalarExt| {
            let words = value.to_canonical_limbs();
            [
                C::Base::from_u128(u128::from(words[0]) | (u128::from(words[1]) << 64)),
                C::Base::from_u128(u128::from(words[2]) | (u128::from(words[3]) << 64)),
            ]
        };
        let public = vec![
            limbs(vanishing.invert().unwrap_or(C::ScalarExt::ONE))
                .into_iter()
                .chain(limbs(weight))
                .chain([C::Base::from(u64::from(valid))])
                .collect::<Vec<_>>(),
        ];
        assert!(
            check_circuit(&circuit, 16, &public, CheckMode::Strict)
                .unwrap()
                .is_satisfied()
        );
        let cells = circuit.inverse_cells.borrow().clone();
        for cell in cells {
            let report = check_tampered(
                &circuit,
                16,
                &public,
                Some(Tamper {
                    column: cell.column.index(),
                    row: cell.row_offset,
                    delta: C::Base::ONE,
                }),
            )
            .unwrap();
            assert!(!report.is_satisfied());
        }
        let known = synthesize(&circuit, 16, Some(&public)).unwrap();
        let unknown = synthesize(&circuit.without_witnesses(), 16, None).unwrap();
        assert_eq!(known.tables.fixed(), unknown.tables.fixed());
        assert_eq!(known.tables.selectors(), unknown.tables.selectors());
        assert_eq!(known.tables.permutation(), unknown.tables.permutation());
        assert_eq!(
            known.tables.advice_assigned(),
            unknown.tables.advice_assigned()
        );
    }
}
#[test]
fn factored_lagrange_zero_denominator_inverse_tampering_and_cache_both_curves() {
    cases::<Ep>();
    cases::<Eq>();
}
