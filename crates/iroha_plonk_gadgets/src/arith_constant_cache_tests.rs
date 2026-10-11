//! Exact fixed-constant cache, clone, region and synthesis boundaries.

use super::*;
use crate::tamper::undetected_tampers;
use iroha_pasta::{Fp, Fq};
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    frontend::{Circuit, Layouter, SimpleFloorPlanner, synthesize},
};

#[derive(Clone)]
struct Cached<F: PastaField> {
    known: bool,
    forge_first: bool,
    forge_hit: bool,
    marker: core::marker::PhantomData<F>,
}
impl<F: PastaField> Circuit<F> for Cached<F> {
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
        let rows = SharedRows::new(RowCursor::bounded(0, 32));
        let mut chip = GlueChip::with_shared_cursor(config, &rows).with_shared_constant_cache()?;
        let value = |v| {
            if self.known {
                Value::known(F::from(v))
            } else {
                Value::unknown()
            }
        };
        let (one, seven) = layouter.assign_region(
            || "first constants",
            |mut region| {
                let one = chip.constant(&mut region, F::ONE)?;
                let row = chip.next_row();
                assert_eq!(chip.constant(&mut region, F::ONE)?.cell(), one.cell());
                assert_eq!(chip.next_row(), row);
                let seven =
                    chip.witness(&mut region, value(if self.forge_first { 8 } else { 7 }))?;
                chip.enforce_constant(&mut region, &seven, F::from(7))?;
                let row = chip.next_row();
                assert_eq!(chip.constant(&mut region, F::from(7))?.cell(), seven.cell());
                assert_eq!(chip.next_row(), row);
                let fresh = chip.witness(&mut region, value(if self.forge_hit { 8 } else { 7 }))?;
                assert_ne!(fresh.cell(), seven.cell());
                let row = chip.next_row();
                chip.enforce_constant(&mut region, &fresh, F::from(7))?;
                assert_eq!(chip.next_row(), row);
                Ok((one, seven))
            },
        )?;
        let mut cloned = chip.clone();
        layouter.assign_region(
            || "cross-region copies",
            |mut region| {
                let row = cloned.next_row();
                assert_eq!(cloned.constant(&mut region, F::ONE)?.cell(), one.cell());
                assert_eq!(
                    cloned.constant(&mut region, F::from(7))?.cell(),
                    seven.cell()
                );
                assert_eq!(cloned.next_row(), row);
                let sum = cloned.add(&mut region, &one, &seven)?;
                cloned.enforce_constant(&mut region, &sum, F::from(8))?;
                assert_eq!(cloned.constant(&mut region, F::from(8))?.cell(), sum.cell());
                // A new explicit cache has no borrowed synthesis state, even when
                // the configured ports and shared reservation cursor are identical.
                let mut fresh =
                    GlueChip::with_shared_cursor(config, &rows).with_shared_constant_cache()?;
                let again = fresh.constant(&mut region, F::ONE)?;
                assert_ne!(again.cell(), one.cell());
                GlueChip::assert_equal(&mut region, &again, &one)?;
                Ok(())
            },
        )
    }
}
fn cases<F: PastaField>() {
    let circuit = Cached::<F> {
        known: true,
        forge_first: false,
        forge_hit: false,
        marker: core::marker::PhantomData,
    };
    assert!(
        check_circuit(&circuit, 8, &[], CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
    for (forge_first, forge_hit) in [(true, false), (false, true), (true, true)] {
        assert!(
            !check_circuit(
                &Cached {
                    forge_first,
                    forge_hit,
                    ..circuit.clone()
                },
                8,
                &[],
                CheckMode::Strict
            )
            .unwrap()
            .is_satisfied()
        );
    }
    let known = synthesize(&circuit, 8, Some(&[])).unwrap();
    let unknown = synthesize(&circuit.without_witnesses(), 8, None).unwrap();
    let repeated = synthesize(&circuit, 8, Some(&[])).unwrap();
    for other in [&unknown, &repeated] {
        assert_eq!(known.tables.fixed(), other.tables.fixed());
        assert_eq!(known.tables.permutation(), other.tables.permutation());
        assert_eq!(
            known.tables.advice_assigned(),
            other.tables.advice_assigned()
        );
    }
    assert!(undetected_tampers(&circuit, 8, &[]).unwrap().is_empty());
    let mut meta = ConstraintSystem::<F>::default();
    let config = Cached::<F>::configure(&mut meta);
    assert!(
        GlueChip::<F>::new(config)
            .with_shared_constant_cache()
            .is_err()
    );
    assert!(
        GlueChip::<F>::with_shared_cursor(config, &SharedRows::new(RowCursor::starting_at(0)))
            .with_shared_constant_cache()
            .is_err()
    );
}
#[test]
fn constant_cache_reuses_only_fixed_pinned_cells_both_fields() {
    cases::<Fp>();
    cases::<Fq>();
}
