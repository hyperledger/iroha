//! Exact-cell GLV split reuse across different points and synthesis regions.

use super::*;
use iroha_pasta::{Ep, Eq, PastaField};
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    frontend::{Circuit, SimpleFloorPlanner, synthesize},
};
use iroha_plonk_gadgets::tamper::{Tamper, check_tampered};
use std::{cell::RefCell, rc::Rc};

#[derive(Clone)]
struct Reuse<C: PastaCurve> {
    known: bool,
    cells: Rc<RefCell<Vec<Cell>>>,
    marker: core::marker::PhantomData<C>,
}
impl<C: PastaCurve> Circuit<C::Base> for Reuse<C> {
    type Config = VerifierConfig<C>;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn configure(meta: &mut ConstraintSystem<C::Base>) -> Self::Config {
        VerifierConfig::configure(meta)
    }
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<C::Base>,
    ) -> Result<(), Error> {
        let mut chip = VerifierChip::<C>::new(config);
        chip.load_tables(&mut layouter)?;
        let mut cells = Vec::new();
        for (region_index, integer) in [2_u64, 2, 3].into_iter().enumerate() {
            layouter.assign_region(
                || "same scalar identity and distinct scalar cells",
                |mut region| {
                    let value = C::ScalarExt::from(integer);
                    let witness = if self.known {
                        Value::known(value.to_canonical_limbs())
                    } else {
                        Value::unknown()
                    };
                    let scalar = chip.arithmetic.ff.witness_canonical(
                        &mut region,
                        Arithmetic::<C>::modulus(),
                        witness,
                    )?;
                    cells.extend(scalar.limbs().iter().map(Word::cell));
                    let generator = C::generator();
                    let point = chip.ecc.constant_point(&mut region, &generator)?;
                    let result = chip.scale_point(&mut region, &point, &scalar)?;
                    assert_eq!(chip.scalar_splits.len(), region_index + 1);
                    let expected = chip.ecc.constant_point(&mut region, &(generator * value))?;
                    EccChip::<C>::assert_equal(&mut region, &result, &expected)?;
                    let rows = chip.range.next_row();
                    let opposite = chip.ecc.constant_point(&mut region, &-generator)?;
                    let result = chip.scale_point(&mut region, &opposite, &scalar)?;
                    assert_eq!(chip.scalar_splits.len(), region_index + 1);
                    assert_eq!(chip.range.next_row(), rows);
                    let expected = chip
                        .ecc
                        .constant_point(&mut region, &(-generator * value))?;
                    EccChip::<C>::assert_equal(&mut region, &result, &expected)?;
                    Ok(())
                },
            )?;
        }
        cells.extend(
            chip.scalar_splits
                .values()
                .flat_map(|v| v.digit_words().map(Word::cell)),
        );
        *self.cells.borrow_mut() = cells;
        Ok(())
    }
}
fn cases<C: PastaCurve>() {
    let circuit = Reuse::<C> {
        known: true,
        cells: Rc::default(),
        marker: core::marker::PhantomData,
    };
    assert!(
        check_circuit(&circuit, 16, &[], CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
    let cells = circuit.cells.borrow().clone();
    for cell in cells {
        // This frontend's row offsets are already absolute; named regions
        // do not reset the chip's shared physical column/row cursor.
        assert!(
            !check_tampered(
                &circuit,
                16,
                &[],
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
    let known = synthesize(&circuit, 16, Some(&[])).unwrap();
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
fn checked_glv_split_cache_binds_cells_regions_and_different_points() {
    cases::<Ep>();
    cases::<Eq>();
}
