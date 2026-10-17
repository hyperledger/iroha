//! Fixed-coefficient spare-cell custody, exact copies and clone/region controls.
use super::*;
use crate::tamper::undetected_tampers;
use iroha_pasta::{Fp, Fq};
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    frontend::{Circuit, Layouter, SimpleFloorPlanner, synthesize},
};
#[derive(Clone)]
struct Pooled<F: PastaField> {
    known: bool,
    wrong: bool,
    marker: core::marker::PhantomData<F>,
}
impl<F: PastaField> Circuit<F> for Pooled<F> {
    type Config = GlueConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let ports = core::array::from_fn(|_| meta.advice_column());
        let phases = PhaseColumns::allocate(meta);
        GlueConfig::configure_phased_without_constants(meta, ports, phases)
    }
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let rows = SharedRows::new(RowCursor::bounded(0, 64));
        let mut chip = GlueChip::with_shared_cursor(config, &rows)
            .with_shared_witness_pool()?
            .with_shared_glue_spare_pool()?;
        let value = |n| {
            if self.known {
                Value::known(F::from(n))
            } else {
                Value::unknown()
            }
        };
        let one = layouter.assign_region(
            || "completed phase-zero rows",
            |mut region| {
                let one = chip.constant(&mut region, F::ONE)?;
                assert_eq!(chip.spare_witnesses.as_ref().unwrap().borrow().len(), 3);
                let before = chip.next_row();
                let words = chip.witnesses(
                    &mut region,
                    &[value(if self.wrong { 3 } else { 2 }), value(3), value(4)],
                )?;
                assert_eq!(chip.next_row(), before);
                for (w, n) in words.iter().zip(2..5) {
                    chip.enforce_constant(&mut region, w, F::from(n))?;
                }
                let product = chip.mul(&mut region, &words[1], &words[2])?;
                chip.enforce_constant(&mut region, &product, F::from(12))?;
                Ok(one)
            },
        )?;
        let mut clone = chip.clone();
        layouter.assign_region(
            || "cloned cross-region spare ownership",
            |mut region| {
                let before = clone.next_row();
                let available = clone.spare_witnesses.as_ref().unwrap().borrow().len();
                assert!(available >= 2);
                let a = clone.witness(&mut region, value(7))?;
                let b = chip.witness(&mut region, value(8))?;
                assert_ne!(a.cell(), b.cell());
                assert_eq!(clone.next_row(), before);
                let sum = clone.add(&mut region, &a, &one)?;
                GlueChip::assert_equal(&mut region, &sum, &b)?;
                clone.enforce_constant(&mut region, &a, F::from(7))?;
                clone.enforce_constant(&mut region, &b, F::from(8))?;
                Ok(())
            },
        )
    }
}
fn cases<F: PastaField>() {
    let c = Pooled::<F> {
        known: true,
        wrong: false,
        marker: core::marker::PhantomData,
    };
    assert!(
        check_circuit(&c, 8, &[], CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
    assert!(
        !check_circuit(
            &Pooled {
                wrong: true,
                ..c.clone()
            },
            8,
            &[],
            CheckMode::Strict
        )
        .unwrap()
        .is_satisfied()
    );
    let k = synthesize(&c, 8, Some(&[])).unwrap();
    let u = synthesize(&c.without_witnesses(), 8, None).unwrap();
    assert_eq!(k.tables.fixed(), u.tables.fixed());
    assert_eq!(k.tables.permutation(), u.tables.permutation());
    assert_eq!(k.tables.advice_assigned(), u.tables.advice_assigned());
    assert!(undetected_tampers(&c, 8, &[]).unwrap().is_empty());
    let mut meta = ConstraintSystem::<F>::default();
    let config = Pooled::<F>::configure(&mut meta);
    assert!(
        GlueChip::<F>::new(config)
            .with_shared_glue_spare_pool()
            .is_err()
    );
    assert!(
        GlueChip::<F>::with_shared_cursor(config, &SharedRows::new(RowCursor::bounded(0, 64)))
            .with_shared_glue_spare_pool()
            .is_err()
    );
}
#[test]
fn glue_spares_preserve_all_cells_copies_and_shape_both_fields() {
    cases::<Fp>();
    cases::<Fq>();
}
