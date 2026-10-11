//! Structural constant batching remains independent of witness values.

use super::*;
use crate::verifier::{VerifierChip, VerifierConfig};
use iroha_pasta::{Ep, Eq};
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::{Column, ConstraintSystem, Instance},
    frontend::{Circuit, Layouter, SimpleFloorPlanner, Value, synthesize},
};
use iroha_plonk_gadgets::{
    Word,
    tamper::{Tamper, check_tampered},
};
use std::{cell::RefCell, rc::Rc};

#[derive(Clone)]
struct Constants<C: PastaCurve> {
    known: bool,
    cells: Rc<RefCell<Vec<Cell>>>,
    marker: PhantomData<C>,
}
fn coefficients<C: PastaCurve>() -> [C::ScalarExt; 8] {
    [
        C::ScalarExt::ZERO,
        C::ScalarExt::ONE,
        -C::ScalarExt::ONE,
        C::ScalarExt::from(128),
        C::ScalarExt::from(129),
        C::ScalarExt::TWO_INV,
        C::ScalarExt::ROOT_OF_UNITY,
        -C::ScalarExt::from(9),
    ]
}
impl<C: PastaCurve> Circuit<C::Base> for Constants<C> {
    type Config = (VerifierConfig<C>, Column<Instance>);
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn configure(meta: &mut ConstraintSystem<C::Base>) -> Self::Config {
        let config = VerifierConfig::configure_serialized_foreign(meta, 2).unwrap();
        let public = meta.instance_column(2);
        meta.enable_equality(public);
        (config, public)
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
        let cells = layouter.assign_region(
            || "constant product batches",
            |mut region| {
                let mut pairs = Vec::new();
                for (index, coefficient) in coefficients::<C>().into_iter().enumerate() {
                    let coefficient = chip.constant(&mut region, coefficient)?;
                    // Witness one deliberately has no constant metadata.
                    let witness = if self.known {
                        Value::known(C::ScalarExt::ONE.to_canonical_limbs())
                    } else {
                        Value::unknown()
                    };
                    let value = chip.arithmetic.ff.witness_canonical(
                        &mut region,
                        Arithmetic::<C>::modulus(),
                        witness,
                    )?;
                    assert_eq!(
                        chip.arithmetic.cheap_product(&coefficient, &value),
                        index < 4
                    );
                    pairs.push((coefficient, value));
                }
                let refs = pairs.iter().map(|(a, b)| (a, b)).collect::<Vec<_>>();
                let result = chip.arithmetic.dot(
                    &mut UintChip::new(&mut chip.glue, &mut chip.range),
                    &mut region,
                    &refs,
                )?;
                *self.cells.borrow_mut() = result.limbs().iter().map(Word::cell).collect();
                let result = chip.export(&mut region, &result)?;
                Ok([result.lo().cell(), result.hi().cell()])
            },
        )?;
        for (row, cell) in cells.into_iter().enumerate() {
            layouter.constrain_instance(cell, public, row)?;
        }
        Ok(())
    }
}
fn cases<C: PastaCurve>() {
    let circuit = Constants::<C> {
        known: true,
        cells: Rc::default(),
        marker: PhantomData,
    };
    let expected = coefficients::<C>()
        .into_iter()
        .fold(C::ScalarExt::ZERO, |a, b| a + b)
        .to_canonical_limbs();
    let public = vec![vec![
        C::Base::from_u128(u128::from(expected[0]) | (u128::from(expected[1]) << 64)),
        C::Base::from_u128(u128::from(expected[2]) | (u128::from(expected[3]) << 64)),
    ]];
    assert!(
        check_circuit(&circuit, 16, &public, CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
    let cells = circuit.cells.borrow().clone();
    for cell in cells {
        assert!(
            !check_tampered(
                &circuit,
                16,
                &public,
                Some(Tamper {
                    column: cell.column.index(),
                    row: cell.row_offset,
                    delta: C::Base::ONE
                })
            )
            .unwrap()
            .is_satisfied()
        );
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
#[test]
fn full_field_constants_batch_and_witness_one_stays_constrained() {
    cases::<Ep>();
    cases::<Eq>();
}
